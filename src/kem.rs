use core::cmp::Ordering;

use rand::{prelude::Distribution, distributions::Standard};
use sha3::{
    Sha3_256, Sha3_512, Shake256,
    digest::{Update, FixedOutput, ExtendableOutput, XofReader},
};
use subtle::{ConstantTimeEq, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    config::{Dim, Config},
    indcpa::{self, split},
};

/// The seed for key pair.
pub struct KeySeed {
    pub main: [u8; 32],
    pub reject: [u8; 32],
}

impl Distribution<KeySeed> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> KeySeed {
        KeySeed {
            main: rng.gen(),
            reject: rng.gen(),
        }
    }
}

/// The secret key. Intended to keep only in RAM, do not store persistently.
/// Store the seed instead.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<const DIM: usize> {
    inner: indcpa::SecretKey<DIM, 32>,
    reject: [u8; 32],
}

/// The public key. Containing its hash. Use `to_bytes` and `from_bytes` to store or transmit.
// public key is also `Zeroize` because one may want to keep in secret the fact they using kyber
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PublicKey<const DIM: usize> {
    inner: indcpa::PublicKey<DIM, 32>,
    hash: [u8; 32],
}

impl<const DIM: usize> PartialEq for PublicKey<DIM> {
    fn eq(&self, other: &Self) -> bool {
        self.hash.eq(&other.hash)
    }
}

impl<const DIM: usize> Eq for PublicKey<DIM> {}

impl<const DIM: usize> PartialOrd for PublicKey<DIM> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.hash.partial_cmp(&other.hash)
    }
}

impl<const DIM: usize> Ord for PublicKey<DIM> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hash.cmp(&other.hash)
    }
}

/// The encapsulated secret. Use `to_bytes` and `from_bytes` to store or transmit.
pub struct CipherText<const DIM: usize> {
    inner: indcpa::CipherText<DIM, 32>,
}

/// Deserialize a key pair from bytes
///
/// # Panics
///
/// will panic if length of bytes not equal to `768 * DIM + 96`
#[must_use]
pub fn load_key_pair<const DIM: usize>(b: &[u8]) -> (SecretKey<DIM>, PublicKey<DIM>) {
    let sk_len = 12 * 32 * DIM;
    let pk_len = 12 * 32 * DIM + 32;
    let pk_hash_len = 32;
    let sk_reject_len = 32;
    assert_eq!(b.len(), sk_len + pk_len + pk_hash_len + sk_reject_len);
    (
        SecretKey {
            inner: indcpa::SecretKey::from_bytes(&b[..sk_len]),
            reject: b[(sk_len + pk_len + pk_hash_len)..].try_into().unwrap(),
        },
        PublicKey {
            inner: indcpa::PublicKey::from_bytes(&b[sk_len..(sk_len + pk_len)]),
            hash: b[(sk_len + pk_len)..(sk_len + pk_len + pk_hash_len)]
                .try_into()
                .unwrap(),
        },
    )
}

/// Creates a key pair from the seed.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn key_pair<const DIM: usize>(s: KeySeed) -> (SecretKey<DIM>, PublicKey<DIM>)
where
    Dim<DIM>: Config<32>,
{
    let KeySeed { mut main, reject } = s;

    let (inner_sk, inner) = indcpa::key_pair(&main);
    main.zeroize();

    let mut sha = Sha3_256::default();
    inner.to_bytes(&mut sha);
    let hash = sha.finalize_fixed().into();

    (
        SecretKey {
            inner: inner_sk,
            reject,
        },
        PublicKey { inner, hash },
    )
}

/// Encapsulates the secret using public key of receiver.
#[must_use]
pub fn encapsulate<const DIM: usize>(
    seed: [u8; 32],
    public_key: &PublicKey<DIM>,
) -> (CipherText<DIM>, [u8; 32])
where
    Dim<DIM>: Config<32>,
{
    let mut seed = seed;
    let mut message = Sha3_256::default().chain(&seed).finalize_fixed().into();
    seed.zeroize();
    let c = Sha3_512::default()
        .chain(&message)
        .chain(&public_key.hash)
        .finalize_fixed();
    let (mut r, mut noise_seed) = split(c.into());

    let inner_ct = indcpa::encapsulate(&noise_seed, &message, &public_key.inner);
    noise_seed.zeroize();
    message.zeroize();

    let mut sha = Sha3_256::default();
    inner_ct.to_bytes(&mut sha);
    let mut ct_hash = sha.finalize_fixed();

    let mut ss = [0; 32];
    let mut xof = Shake256::default().chain(&r).chain(&ct_hash).finalize_xof();
    xof.read(&mut ss);

    r.zeroize();
    ct_hash.zeroize();

    (CipherText { inner: inner_ct }, ss)
}

/// Decapsulate the secret from cipher text using secret key.
#[must_use]
pub fn decapsulate<const DIM: usize>(
    secret_key: &SecretKey<DIM>,
    public_key: &PublicKey<DIM>,
    cipher_text: &CipherText<DIM>,
) -> [u8; 32]
where
    Dim<DIM>: Config<32>,
{
    let mut message = indcpa::decapsulate(&cipher_text.inner, &secret_key.inner);
    let c = Sha3_512::default()
        .chain(&message)
        .chain(&public_key.hash)
        .finalize_fixed();
    let (mut r, mut noise_seed) = split(c.into());

    let inner_ct = indcpa::encapsulate(&noise_seed, &message, &public_key.inner);
    let flag = inner_ct.ct_eq(&cipher_text.inner);
    noise_seed.zeroize();
    message.zeroize();

    let mut sha = Sha3_256::default();
    inner_ct.to_bytes(&mut sha);
    let mut ct_hash = sha.finalize_fixed();

    // TODO:
    secret_key
        .reject
        .iter()
        .zip(r.iter_mut())
        .for_each(|(a, b)| b.conditional_assign(a, !flag));

    let mut ss = [0; 32];
    let mut xof = Shake256::default().chain(&r).chain(&ct_hash).finalize_xof();
    xof.read(&mut ss);

    r.zeroize();
    ct_hash.zeroize();

    ss
}

impl<const DIM: usize> PublicKey<DIM> {
    #[must_use]
    pub const fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn to_bytes<U>(&self, buffer: &mut U)
    where
        U: Update,
    {
        self.inner.to_bytes(buffer);
    }

    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Self {
        let hash = Sha3_256::default().chain(b).finalize_fixed().into();

        PublicKey {
            inner: indcpa::PublicKey::from_bytes(b),
            hash,
        }
    }
}

impl<const DIM: usize> CipherText<DIM>
where
    Dim<DIM>: Config<32>,
{
    pub fn to_bytes<U>(&self, buffer: &mut U)
    where
        U: Update,
    {
        self.inner.to_bytes(buffer);
    }

    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Self {
        CipherText {
            inner: indcpa::CipherText::from_bytes(b),
        }
    }
}
