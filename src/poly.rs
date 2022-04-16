use core::ops::{Index, IndexMut, AddAssign, SubAssign};

use sha3::digest::{Update, ExtendableOutput, XofReader};

use super::{array::Array, coefficient::Coefficient, block::PolyBlock, generator::Buf};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Poly<const SIZE: usize, const B: bool>(Array<PolyBlock, SIZE>);

impl<const SIZE: usize, const B: bool> Index<usize> for Poly<SIZE, B> {
    type Output = Coefficient;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index / 8][index % 8]
    }
}

impl<const SIZE: usize, const B: bool> IndexMut<usize> for Poly<SIZE, B> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index / 8][index % 8]
    }
}

impl<'a, const SIZE: usize, const B: bool> AddAssign<&'a Self> for Poly<SIZE, B> {
    fn add_assign(&mut self, rhs: &'a Self) {
        for i in 0..(SIZE * 8) {
            self[i] = self[i] + rhs[i];
        }
    }
}

impl<'a, const SIZE: usize, const B: bool> SubAssign<&'a Self> for Poly<SIZE, B> {
    fn sub_assign(&mut self, rhs: &'a Self) {
        for i in 0..(SIZE * 8) {
            self[i] = self[i] - rhs[i];
        }
    }
}

pub trait PolyMul {
    fn mul_montgomery(&self, rhs: &Self) -> Self;

    fn mul_fold_montgomery<'a, 'b, A, B, Br>(a: A, b: B) -> Self
    where
        Self: 'a + 'b,
        A: Iterator<Item = &'a Self>,
        B: Iterator<Item = Br>,
        Br: AsRef<Self>;
}

impl<const SIZE: usize> AsRef<Self> for Poly<SIZE, false> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl PolyMul for Poly<32, false> {
    #[must_use]
    fn mul_montgomery(&self, rhs: &Self) -> Self {
        let array = (0..32)
            .map(|i| {
                let zetas = [
                    Coefficient(ZETAS[64 + 2 * i]),
                    Coefficient(ZETAS[64 + 2 * i + 1]),
                ];
                self.0[i].mul(&rhs.0[i], zetas)
            })
            .collect();

        Poly(array)
    }

    #[must_use]
    fn mul_fold_montgomery<'a, 'b, A, B, Br>(mut a: A, mut b: B) -> Self
    where
        Self: 'a + 'b,
        A: Iterator<Item = &'a Self>,
        B: Iterator<Item = Br>,
        Br: AsRef<Self>,
    {
        let af = a.next().expect("not empty iterator");
        let bf = b.next().expect("not empty iterator");
        let init = af.mul_montgomery(bf.as_ref());
        let p = a.zip(b).fold(init, |mut r, (a, b)| {
            r += &a.mul_montgomery(b.as_ref());
            r
        });
        p.barrett_reduce()
    }
}

impl<const SIZE: usize, const B: bool> Poly<SIZE, B> {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Poly(bytes.chunks(12).map(PolyBlock::from_bytes).collect())
    }

    pub fn to_bytes<U>(self, update: &mut U)
    where
        U: Update,
    {
        for a in self.0.as_ref() {
            update.update(&a.to_bytes());
        }
    }

    #[must_use]
    pub fn barrett_reduce(mut self) -> Self {
        for i in 0..(SIZE * 8) {
            self[i] = Coefficient::barrett_reduce(self[i].0);
        }
        self
    }
}

impl<const SIZE: usize> Poly<SIZE, false> {
    pub fn get_uniform<D>(seed: &[u8; 32], i: usize, j: usize) -> Self
    where
        D: Default + Update + ExtendableOutput,
    {
        let mut it = Buf::new::<D>(seed, i, j)
            .filter(|x| x.lt(&Coefficient::Q))
            .map(Coefficient);
        Poly((0..SIZE).map(|_| PolyBlock::new(&mut it)).collect())
    }

    #[must_use]
    pub fn montgomery_reduce(mut self) -> Self {
        let f = ((1u64 << 32) % Coefficient::Q as u64) as i16;
        for i in 0..(SIZE * 8) {
            self[i] = self[i] * Coefficient(f);
        }
        self
    }
}

impl<const SIZE: usize> Poly<SIZE, true> {
    pub fn get_noise<D, const I: usize>(seed: &[u8; 32], nonce: usize) -> Self
    where
        D: Default + Update + ExtendableOutput,
    {
        let mut reader = D::default()
            .chain(seed)
            .chain([nonce as u8].as_ref())
            .finalize_xof();

        let array = (0..SIZE)
            .map(|_| {
                let mut b = [0; I];
                reader.read(b.as_mut());
                PolyBlock::cbd(b)
            })
            .collect();

        Poly(array)
    }

    pub fn compress<U, const X: u32>(self, update: &mut U)
    where
        U: Update,
    {
        for a in self.0.as_ref() {
            match X {
                4 => update.update(&a.compress_4()),
                5 => update.update(&a.compress_5()),
                10 => update.update(&a.compress_10()),
                11 => update.update(&a.compress_11()),
                _ => unimplemented!(),
            }
        }
    }

    pub fn decompress<const X: u32>(bytes: &[u8]) -> Self {
        Poly(
            bytes
                .chunks(X as usize)
                .map(PolyBlock::decompress::<X>)
                .collect(),
        )
    }

    pub fn from_msg(msg: &[u8; SIZE]) -> Self {
        Poly(msg.iter().copied().map(PolyBlock::decompress_1).collect())
    }

    pub fn to_msg(self) -> [u8; SIZE] {
        let mut b = [0; SIZE];
        for (a, b) in self.0.as_ref().iter().zip(b.iter_mut()) {
            *b = a.compress_1();
        }
        b
    }
}

pub trait Ntt {
    type Output: Ntt;

    fn ntt(self) -> Self::Output;
}

const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

impl Ntt for Poly<32, true> {
    type Output = Poly<32, false>;

    #[must_use]
    fn ntt(self) -> Self::Output {
        let mut r = Poly(self.0);

        let mut j;
        let mut k = 1usize;
        let mut len = 128;

        while len >= 2 {
            let mut start = 0;
            while start < 256 {
                let zeta = Coefficient(ZETAS[k]);
                k += 1;
                j = start;
                while j < (start + len) {
                    let t = zeta * r[j + len];
                    r[j + len] = r[j] - t;
                    r[j] = r[j] + t;
                    j += 1;
                }
                start = j + len;
            }
            len >>= 1;
        }
        r.barrett_reduce()
    }
}

impl Ntt for Poly<32, false> {
    type Output = Poly<32, true>;

    #[must_use]
    fn ntt(self) -> Self::Output {
        let mut r = Poly(self.0);

        let mut j;
        let mut k = 127;
        let mut len = 2;

        while len <= 128 {
            let mut start = 0;
            while start < 256 {
                let zeta = Coefficient(ZETAS[k]);
                k -= 1;
                j = start;
                while j < (start + len) {
                    let t = r[j];
                    r[j] = t + r[j + len];
                    r[j + len] = r[j + len] - t;
                    r[j + len] = zeta * r[j + len];
                    j += 1;
                }
                start = j + len;
            }
            len <<= 1;
        }
        for j in 0..256 {
            r[j] = r[j] * Coefficient::F;
        }

        r
    }
}
