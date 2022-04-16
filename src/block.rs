use core::ops::{Index, IndexMut};

use super::{array::Array, coefficient::Coefficient};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PolyBlock(Array<Coefficient, 8>);

impl PolyBlock {
    #[inline]
    pub fn new<I>(it: &mut I) -> Self
    where
        I: Iterator<Item = Coefficient>,
    {
        PolyBlock(Array::new(it))
    }
}

impl Index<usize> for PolyBlock {
    type Output = Coefficient;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for PolyBlock {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl PolyBlock {
    #[inline]
    pub fn decompress<const X: u32>(b: &[u8]) -> Self {
        match X {
            4 => Self::decompress_4(b),
            5 => Self::decompress_5(b),
            10 => Self::decompress_10(b),
            11 => Self::decompress_11(b),
            _ => unimplemented!(),
        }
    }

    #[inline]
    pub fn compress_4(&self) -> [u8; 4] {
        let t = |j: usize| self.0[j].compress::<4>() as u8;
        [
            t(0) | (t(1) << 4),
            t(2) | (t(3) << 4),
            t(4) | (t(5) << 4),
            t(6) | (t(7) << 4),
        ]
    }

    #[inline]
    fn decompress_4(b: &[u8]) -> Self {
        let array = b
            .iter()
            .flat_map(|x| {
                [
                    Coefficient::decompress::<4>(u16::from(*x)),
                    Coefficient::decompress::<4>(u16::from(x >> 4)),
                ]
            })
            .collect();
        PolyBlock(array)
    }

    #[inline]
    pub fn compress_5(&self) -> [u8; 5] {
        let t = |j: usize| self.0[j].compress::<5>() as u8;
        [
            t(0) | (t(1) << 5),
            (t(1) >> 3) | (t(2) << 2) | (t(3) << 7),
            (t(3) >> 1) | (t(4) << 4),
            (t(4) >> 4) | (t(5) << 1) | (t(6) << 6),
            (t(6) >> 2) | (t(7) << 3),
        ]
    }

    #[inline]
    fn decompress_5(b: &[u8]) -> Self {
        let array = [
            Coefficient::decompress::<5>(u16::from(b[0])),
            Coefficient::decompress::<5>(u16::from(b[0] >> 5 | b[1] << 3)),
            Coefficient::decompress::<5>(u16::from(b[1] >> 2)),
            Coefficient::decompress::<5>(u16::from(b[1] >> 7 | b[2] << 1)),
            Coefficient::decompress::<5>(u16::from(b[2] >> 4 | b[3] << 4)),
            Coefficient::decompress::<5>(u16::from(b[3] >> 1)),
            Coefficient::decompress::<5>(u16::from(b[3] >> 6 | b[4] << 2)),
            Coefficient::decompress::<5>(u16::from(b[4] >> 3)),
        ]
        .into_iter()
        .collect();
        PolyBlock(array)
    }

    #[inline]
    pub fn compress_10(&self) -> [u8; 10] {
        let t = |j: usize| self.0[j].compress::<10>();
        [
            t(0) as u8,
            ((t(0) >> 8) | (t(1) << 2)) as u8,
            ((t(1) >> 6) | (t(2) << 4)) as u8,
            ((t(2) >> 4) | (t(3) << 6)) as u8,
            (t(3) >> 2) as u8,
            t(4) as u8,
            ((t(4) >> 8) | (t(5) << 2)) as u8,
            ((t(5) >> 6) | (t(6) << 4)) as u8,
            ((t(6) >> 4) | (t(7) << 6)) as u8,
            (t(7) >> 2) as u8,
        ]
    }

    #[inline]
    fn decompress_10(b: &[u8]) -> Self {
        let array = [
            Coefficient::decompress::<10>(u16::from(b[0]) | u16::from(b[1]) << 8),
            Coefficient::decompress::<10>(u16::from(b[1] >> 2) | u16::from(b[2]) << 6),
            Coefficient::decompress::<10>(u16::from(b[2] >> 4) | u16::from(b[3]) << 4),
            Coefficient::decompress::<10>(u16::from(b[3] >> 6) | u16::from(b[4]) << 2),
            Coefficient::decompress::<10>(u16::from(b[5]) | u16::from(b[6]) << 8),
            Coefficient::decompress::<10>(u16::from(b[6] >> 2) | u16::from(b[7]) << 6),
            Coefficient::decompress::<10>(u16::from(b[7] >> 4) | u16::from(b[8]) << 4),
            Coefficient::decompress::<10>(u16::from(b[8] >> 6) | u16::from(b[9]) << 2),
        ]
        .into_iter()
        .collect();
        PolyBlock(array)
    }

    #[inline]
    pub fn compress_11(&self) -> [u8; 11] {
        let t = |j: usize| self.0[j].compress::<11>();
        [
            t(0) as u8,
            ((t(0) >> 8) | (t(1) << 3)) as u8,
            ((t(1) >> 5) | (t(2) << 6)) as u8,
            (t(2) >> 2) as u8,
            ((t(2) >> 10) | (t(3) << 1)) as u8,
            ((t(3) >> 7) | (t(4) << 4)) as u8,
            ((t(4) >> 4) | (t(5) << 7)) as u8,
            (t(5) >> 1) as u8,
            ((t(5) >> 9) | (t(6) << 2)) as u8,
            ((t(6) >> 6) | (t(7) << 5)) as u8,
            (t(7) >> 3) as u8,
        ]
    }

    #[inline]
    fn decompress_11(b: &[u8]) -> Self {
        let array = [
            Coefficient::decompress::<11>(u16::from(b[0]) | u16::from(b[1]) << 8),
            Coefficient::decompress::<11>(u16::from(b[1] >> 3) | u16::from(b[2]) << 5),
            Coefficient::decompress::<11>(
                u16::from(b[2] >> 6) | u16::from(b[3]) << 2 | u16::from(b[4]) << 10,
            ),
            Coefficient::decompress::<11>(u16::from(b[4] >> 1) | u16::from(b[5]) << 7),
            Coefficient::decompress::<11>(u16::from(b[5] >> 4) | u16::from(b[6]) << 4),
            Coefficient::decompress::<11>(
                u16::from(b[6] >> 7) | u16::from(b[7]) << 1 | u16::from(b[8]) << 9,
            ),
            Coefficient::decompress::<11>(u16::from(b[8] >> 2) | u16::from(b[9]) << 6),
            Coefficient::decompress::<11>(u16::from(b[9] >> 5) | u16::from(b[10]) << 3),
        ]
        .into_iter()
        .collect();
        PolyBlock(array)
    }

    #[inline]
    pub fn compress_1(&self) -> u8 {
        (0..8).fold(0, |b, j| b | (self.0[j].compress_1() << j))
    }

    #[inline]
    pub fn decompress_1(b: u8) -> Self {
        let array = (0..8).map(|j| Coefficient::decompress_1(b >> j)).collect();
        PolyBlock(array)
    }

    #[inline]
    pub fn to_bytes(self) -> [u8; 12] {
        let mut r = [0; 12];

        for i in 0..4 {
            // map to positive standard representatives
            let t0 = self.0[2 * i].pack();
            let t1 = self.0[2 * i + 1].pack();
            r[3 * i] = t0 as u8;
            r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
            r[3 * i + 2] = (t1 >> 4) as u8;
        }
        r
    }

    #[inline]
    pub fn from_bytes(b: &[u8]) -> Self {
        let array = b
            .chunks(3)
            .flat_map(|b| {
                let t0 = u16::from(b[0]) | (u16::from(b[1]) << 8);
                let t1 = u16::from(b[1] >> 4) | (u16::from(b[2]) << 4);
                [
                    Coefficient::unpack(t0 & 0xfff),
                    Coefficient::unpack(t1 & 0xfff),
                ]
            })
            .collect();
        PolyBlock(array)
    }

    #[inline]
    pub fn mul(&self, rhs: &Self, zetas: [Coefficient; 2]) -> Self {
        use core::mem::MaybeUninit;
        PolyBlock(Array::initialize([
            MaybeUninit::new(self.0[0] * rhs.0[0] + self.0[1] * rhs.0[1] * zetas[0]),
            MaybeUninit::new(self.0[0] * rhs.0[1] + self.0[1] * rhs.0[0]),
            MaybeUninit::new(self.0[2] * rhs.0[2] - self.0[3] * rhs.0[3] * zetas[0]),
            MaybeUninit::new(self.0[2] * rhs.0[3] + self.0[3] * rhs.0[2]),
            MaybeUninit::new(self.0[4] * rhs.0[4] + self.0[5] * rhs.0[5] * zetas[1]),
            MaybeUninit::new(self.0[4] * rhs.0[5] + self.0[5] * rhs.0[4]),
            MaybeUninit::new(self.0[6] * rhs.0[6] - self.0[7] * rhs.0[7] * zetas[1]),
            MaybeUninit::new(self.0[6] * rhs.0[7] + self.0[7] * rhs.0[6]),
        ]))
    }

    /// centered binomial distribution
    #[inline]
    pub fn cbd<const N: usize>(v: [u8; N]) -> Self {
        let array = match N {
            6 => v
                .as_ref()
                .chunks(3)
                .flat_map(|v| {
                    let mut a = [0; 4];
                    a[0..3].clone_from_slice(v);
                    let t = u32::from_le_bytes(a);
                    let d = (0..3).map(|j| (t >> j) & 0o11_111_111).sum::<u32>();

                    (0..4).map(move |k| {
                        let mask = (1 << 3) - 1;
                        let a = (d >> (6 * k)) & mask;
                        let b = (d >> ((6 * k) + 3)) & mask;
                        Coefficient::unpack((a as i32 - b as i32) as u16)
                    })
                })
                .collect(),
            4 => {
                let t = u32::from_le_bytes(v[..4].try_into().unwrap());
                let d = (0..2).map(|j| (t >> j) & 0x5555_5555).sum::<u32>();

                (0..8)
                    .map(|k| {
                        let mask = (1 << 2) - 1;
                        let a = (d >> (4 * k)) & mask;
                        let b = (d >> ((4 * k) + 2)) & mask;
                        Coefficient::unpack((a as i32 - b as i32) as u16)
                    })
                    .collect()
            }
            _ => unimplemented!(),
        };

        PolyBlock(array)
    }
}
