use sha3::{Shake256, digest::Update};
use subtle::{Choice, ConstantTimeEq};

use super::{coefficient::Coefficient, poly::Poly};

pub trait Config<const SIZE: usize> {
    const COMPRESSED_SIZE: usize;

    fn get_noise(seed: &[u8; 32], nonce: usize) -> Poly<SIZE, true>;

    fn decompress_vec(bytes: &[u8]) -> Poly<SIZE, true>;

    fn compress_vec<U>(poly: &Poly<SIZE, true>, update: &mut U)
    where
        U: Update;

    fn compare_vec(lhs: &Coefficient, rhs: &Coefficient) -> Choice;

    fn decompress(bytes: &[u8]) -> Poly<SIZE, true>;

    fn compress<U>(poly: &Poly<SIZE, true>, update: &mut U)
    where
        U: Update;

    fn compare(lhs: &Coefficient, rhs: &Coefficient) -> Choice;
}

pub struct Dim<const DIM: usize>;

impl<const SIZE: usize> Config<SIZE> for Dim<2> {
    const COMPRESSED_SIZE: usize = 10 * SIZE;

    #[inline]
    fn get_noise(seed: &[u8; 32], nonce: usize) -> Poly<SIZE, true> {
        Poly::get_noise::<Shake256, 6>(seed, nonce)
    }

    #[inline]
    fn decompress_vec(bytes: &[u8]) -> Poly<SIZE, true> {
        Poly::decompress::<10>(bytes)
    }

    #[inline]
    fn compress_vec<U>(poly: &Poly<SIZE, true>, update: &mut U)
    where
        U: Update,
    {
        poly.compress::<U, 10>(update);
    }

    #[inline]
    fn compare_vec(lhs: &Coefficient, rhs: &Coefficient) -> Choice {
        let ai = lhs.compress::<10>();
        let bi = rhs.compress::<10>();
        ai.ct_eq(&bi)
    }

    #[inline]
    fn decompress(bytes: &[u8]) -> Poly<SIZE, true> {
        Poly::decompress::<4>(bytes)
    }

    #[inline]
    fn compress<U>(poly: &Poly<SIZE, true>, update: &mut U)
    where
        U: Update,
    {
        poly.compress::<U, 4>(update);
    }

    #[inline]
    fn compare(lhs: &Coefficient, rhs: &Coefficient) -> Choice {
        let ai = lhs.compress::<4>();
        let bi = rhs.compress::<4>();
        ai.ct_eq(&bi)
    }
}

impl<const SIZE: usize> Config<SIZE> for Dim<3> {
    const COMPRESSED_SIZE: usize = 10 * SIZE;

    #[inline]
    fn get_noise(seed: &[u8; 32], nonce: usize) -> Poly<SIZE, true> {
        Poly::get_noise::<Shake256, 4>(seed, nonce)
    }

    #[inline]
    fn decompress_vec(bytes: &[u8]) -> Poly<SIZE, true> {
        Poly::decompress::<10>(bytes)
    }

    #[inline]
    fn compress_vec<U>(poly: &Poly<SIZE, true>, update: &mut U)
    where
        U: Update,
    {
        poly.compress::<U, 10>(update);
    }

    #[inline]
    fn compare_vec(lhs: &Coefficient, rhs: &Coefficient) -> Choice {
        let ai = lhs.compress::<10>();
        let bi = rhs.compress::<10>();
        ai.ct_eq(&bi)
    }

    #[inline]
    fn decompress(bytes: &[u8]) -> Poly<SIZE, true> {
        Poly::decompress::<4>(bytes)
    }

    #[inline]
    fn compress<U>(poly: &Poly<SIZE, true>, update: &mut U)
    where
        U: Update,
    {
        poly.compress::<U, 4>(update);
    }

    #[inline]
    fn compare(lhs: &Coefficient, rhs: &Coefficient) -> Choice {
        let ai = lhs.compress::<4>();
        let bi = rhs.compress::<4>();
        ai.ct_eq(&bi)
    }
}

impl<const SIZE: usize> Config<SIZE> for Dim<4> {
    const COMPRESSED_SIZE: usize = 11 * SIZE;

    #[inline]
    fn get_noise(seed: &[u8; 32], nonce: usize) -> Poly<SIZE, true> {
        Poly::get_noise::<Shake256, 4>(seed, nonce)
    }

    #[inline]
    fn decompress_vec(bytes: &[u8]) -> Poly<SIZE, true> {
        Poly::decompress::<11>(bytes)
    }

    #[inline]
    fn compress_vec<U>(poly: &Poly<SIZE, true>, update: &mut U)
    where
        U: Update,
    {
        poly.compress::<U, 11>(update);
    }

    #[inline]
    fn compare_vec(lhs: &Coefficient, rhs: &Coefficient) -> Choice {
        let ai = lhs.compress::<11>();
        let bi = rhs.compress::<11>();
        ai.ct_eq(&bi)
    }

    #[inline]
    fn decompress(bytes: &[u8]) -> Poly<SIZE, true> {
        Poly::decompress::<5>(bytes)
    }

    #[inline]
    fn compress<U>(poly: &Poly<SIZE, true>, update: &mut U)
    where
        U: Update,
    {
        poly.compress::<U, 5>(update);
    }

    #[inline]
    fn compare(lhs: &Coefficient, rhs: &Coefficient) -> Choice {
        let ai = lhs.compress::<5>();
        let bi = rhs.compress::<5>();
        ai.ct_eq(&bi)
    }
}
