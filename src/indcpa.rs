use sha3::{
    Sha3_512, Shake256, Shake128,
    digest::{Update, FixedOutput},
};
use subtle::{ConstantTimeEq, Choice};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    array::Array,
    poly::{Poly, Ntt, PolyMul},
    config::{Dim, Config},
};

#[derive(Clone)]
pub struct SecretKey<const DIM: usize, const SIZE: usize> {
    poly_vector: Array<Poly<SIZE, false>, DIM>,
}

impl<const DIM: usize, const SIZE: usize> ZeroizeOnDrop for SecretKey<DIM, SIZE> {}

impl<const DIM: usize, const SIZE: usize> Zeroize for SecretKey<DIM, SIZE> {
    fn zeroize(&mut self) {
        for v in self.poly_vector.as_mut() {
            for i in 0..(SIZE * 8) {
                v[i].zeroize();
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey<const DIM: usize, const SIZE: usize> {
    poly_vector: Array<Poly<SIZE, false>, DIM>,
    matrix: Array<Array<Poly<SIZE, false>, DIM>, DIM>,
    seed: [u8; 32],
}

impl<const DIM: usize, const SIZE: usize> ZeroizeOnDrop for PublicKey<DIM, SIZE> {}

impl<const DIM: usize, const SIZE: usize> Zeroize for PublicKey<DIM, SIZE> {
    fn zeroize(&mut self) {
        for v in self.poly_vector.as_mut() {
            for i in 0..(SIZE * 8) {
                v[i].zeroize();
            }
        }

        for row in self.matrix.as_mut() {
            for v in row.as_mut() {
                for i in 0..(SIZE * 8) {
                    v[i].zeroize();
                }
            }
        }

        self.seed.zeroize();
    }
}

pub struct CipherText<const DIM: usize, const SIZE: usize> {
    poly_vector: Array<Poly<SIZE, true>, DIM>,
    poly: Poly<SIZE, true>,
}

pub fn split(mut x: [u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut a = [0; 32];
    a.clone_from_slice(&x[..32]);
    let mut b = [0; 32];
    b.clone_from_slice(&x[32..]);
    x.zeroize();
    (a, b)
}

pub fn key_pair<const DIM: usize, const SIZE: usize>(
    seed: &[u8; 32],
) -> (SecretKey<DIM, SIZE>, PublicKey<DIM, SIZE>)
where
    Dim<DIM>: Config<SIZE>,
    Poly<SIZE, false>: PolyMul,
    Poly<SIZE, true>: Ntt<Output = Poly<SIZE, false>>,
{
    let c = Sha3_512::default().chain(seed).finalize_fixed().into();
    let (seed, mut noise_seed) = split(c);

    let sk_pv: Array<_, DIM> = (0..DIM)
        .map(|i| <Dim<DIM> as Config<SIZE>>::get_noise(&noise_seed, i).ntt())
        .collect();

    let a: Array<Array<Poly<SIZE, false>, DIM>, DIM> = (0..DIM)
        .map(|i| {
            (0..DIM)
                .map(|j| Poly::get_uniform::<Shake128>(&seed, i, j))
                .collect()
        })
        .collect();

    let pk_pv: Array<Poly<SIZE, false>, DIM> = (0..DIM)
        .map(|i| {
            let row = (0..DIM).map(|j| &a[j][i]);
            let mut p = Poly::mul_fold_montgomery(row, sk_pv.as_ref().iter()).montgomery_reduce();
            let e = <Dim<DIM> as Config<SIZE>>::get_noise(&noise_seed, DIM + i).ntt();
            p += &e;
            p.barrett_reduce()
        })
        .collect();

    noise_seed.zeroize();

    let sk = SecretKey { poly_vector: sk_pv };
    let pk = PublicKey {
        poly_vector: pk_pv,
        matrix: a,
        seed,
    };

    (sk, pk)
}

pub fn encapsulate<const DIM: usize, const SIZE: usize>(
    noise_seed: &[u8; 32],
    message: &[u8; SIZE],
    public_key: &PublicKey<DIM, SIZE>,
) -> CipherText<DIM, SIZE>
where
    Dim<DIM>: Config<SIZE>,
    Poly<SIZE, false>: PolyMul + Ntt<Output = Poly<SIZE, true>>,
    Poly<SIZE, true>: Ntt<Output = Poly<SIZE, false>>,
{
    let sp: Array<_, DIM> = (0..DIM)
        .map(|i| <Dim<DIM> as Config<SIZE>>::get_noise(noise_seed, i).ntt())
        .collect();

    let a = &public_key.matrix;
    let pk_pv = &public_key.poly_vector;

    let b = (0..DIM)
        .map(|i| {
            let mut b = Poly::mul_fold_montgomery(a[i].as_ref().iter(), sp.as_ref().iter()).ntt();
            b += &Poly::get_noise::<Shake256, 4>(noise_seed, i + DIM);
            b.barrett_reduce()
        })
        .collect();
    let mut v = Poly::mul_fold_montgomery(pk_pv.as_ref().iter(), sp.as_ref().iter()).ntt();
    v += &Poly::get_noise::<Shake256, 4>(noise_seed, 2 * DIM);
    v += &Poly::from_msg(message);

    CipherText {
        poly_vector: b,
        poly: v,
    }
}

pub fn decapsulate<const DIM: usize, const SIZE: usize>(
    cipher_text: &CipherText<DIM, SIZE>,
    secret_key: &SecretKey<DIM, SIZE>,
) -> [u8; SIZE]
where
    Poly<SIZE, false>: PolyMul + Ntt<Output = Poly<SIZE, true>>,
    Poly<SIZE, true>: Ntt<Output = Poly<SIZE, false>>,
{
    let b = &cipher_text.poly_vector;
    let v = &cipher_text.poly;
    let sk_pv = &secret_key.poly_vector;

    let mut mp =
        Poly::mul_fold_montgomery(sk_pv.as_ref().iter(), b.as_ref().iter().map(|b| b.ntt())).ntt();
    mp -= v;
    mp.barrett_reduce().to_msg()
}

impl<const DIM: usize, const SIZE: usize> SecretKey<DIM, SIZE> {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let poly_vector = bytes.chunks(12 * SIZE).map(Poly::from_bytes).collect();

        SecretKey { poly_vector }
    }
}

impl<const DIM: usize, const SIZE: usize> PublicKey<DIM, SIZE> {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let pk_pv = bytes
            .chunks(12 * SIZE)
            .take(DIM)
            .map(Poly::from_bytes)
            .collect();
        let seed = bytes[(12 * SIZE * DIM)..].try_into().unwrap();
        let a = (0..DIM)
            .map(|i| {
                (0..DIM)
                    .map(|j| Poly::get_uniform::<Shake128>(&seed, i, j))
                    .collect()
            })
            .collect();

        PublicKey {
            poly_vector: pk_pv,
            matrix: a,
            seed,
        }
    }

    pub fn to_bytes<U>(&self, update: &mut U)
    where
        U: Update,
    {
        for p in self.poly_vector.as_ref() {
            p.to_bytes(update);
        }
        update.update(&self.seed);
    }
}

impl<const DIM: usize, const SIZE: usize> CipherText<DIM, SIZE>
where
    Dim<DIM>: Config<SIZE>,
{
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let v = <Dim<DIM> as Config<SIZE>>::COMPRESSED_SIZE;
        CipherText {
            poly_vector: bytes
                .chunks(v)
                .take(DIM)
                .map(<Dim<DIM> as Config<SIZE>>::decompress_vec)
                .collect(),
            poly: <Dim<DIM> as Config<SIZE>>::decompress(&bytes[(v * DIM)..]),
        }
    }

    pub fn to_bytes<U>(&self, update: &mut U)
    where
        U: Update,
    {
        for p in self.poly_vector.as_ref() {
            <Dim<DIM> as Config<SIZE>>::compress_vec(p, update);
        }
        <Dim<DIM> as Config<SIZE>>::compress(&self.poly, update);
    }
}

impl<const DIM: usize, const SIZE: usize> ConstantTimeEq for CipherText<DIM, SIZE>
where
    Dim<DIM>: Config<SIZE>,
{
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut x = 1u8;
        for i in 0..DIM {
            for j in 0..SIZE {
                let flag = <Dim<DIM> as Config<SIZE>>::compare_vec(
                    &self.poly_vector[i][j],
                    &other.poly_vector[i][j],
                );
                x &= flag.unwrap_u8();
            }
        }
        for j in 0..SIZE {
            let flag = <Dim<DIM> as Config<SIZE>>::compare(&self.poly[j], &other.poly[j]);
            x &= flag.unwrap_u8();
        }

        x.into()
    }
}
