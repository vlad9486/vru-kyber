use core::ops::{Add, Sub, Mul};

use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct Coefficient(pub i16);

impl Coefficient {
    pub const Q: i16 = 3329;

    // -inverse_mod(q,2^16)
    const Q_INV: i32 = 62209;

    const MONT: Self = Coefficient(-1044);

    pub const F: Self = Coefficient(1441);

    #[inline]
    const fn montgomery_reduce(a: i32) -> Self {
        let ua = a.wrapping_mul(Self::Q_INV) as i16;
        let mut t = (ua as i32) * (Self::Q as i32);
        t = a - t;
        t >>= 16;
        Coefficient(t as i16)
    }

    #[inline]
    pub const fn barrett_reduce(a: i16) -> Self {
        let v = ((1u32 << 26) / (Self::Q as u32) + 1) as i32;
        let mut t = v * (a as i32) + (1 << 25);
        t >>= 26;
        t *= Self::Q as i32;
        Coefficient(a - t as i16)
    }

    #[inline]
    pub const fn pack(self) -> u16 {
        let mut u = self.0;
        u += (u >> 15) & Self::Q;
        u as u16
    }

    #[inline]
    pub const fn unpack(a: u16) -> Self {
        Coefficient(a as i16)
    }

    #[inline]
    pub const fn compress<const X: u32>(self) -> u16 {
        let mask = (1 << X) - 1;
        (((((self.pack() as u32) << X) + Self::Q as u32 / 2) / Self::Q as u32) & mask) as u16
    }

    #[inline]
    pub fn decompress<const X: u32>(b: u16) -> Self {
        let mask = (1 << X) - 1;
        let add = 1 << (X - 1);
        Coefficient((((i32::from(b) & mask) * i32::from(Self::Q) + add) >> X) as i16)
    }

    #[inline]
    pub const fn compress_1(self) -> u8 {
        let mut t = self.pack() as i16;
        t = (((t << 1) + Coefficient::Q / 2) / Coefficient::Q) & 1;
        t as u8
    }

    #[inline]
    pub const fn decompress_1(b: u8) -> Self {
        let mask = ((b as u16) & 1).wrapping_neg();
        Coefficient((mask & ((Coefficient::Q + 1) / 2) as u16) as i16)
    }

    #[inline]
    const fn mul(self, rhs: Self) -> Self {
        Self::montgomery_reduce((self.0 as i32) * (rhs.0 as i32))
    }

    #[inline]
    #[allow(dead_code)]
    pub const fn zeta(i: usize, bits: u32) -> Self {
        #[inline]
        const fn reverse_bits(mut i: usize, mut bits: u32) -> usize {
            let mut r = 0;
            while bits > 0 {
                r *= 2;
                r |= i % 2;
                i /= 2;
                bits -= 1;
            }
            r
        }

        #[inline]
        const fn tmp(i: usize) -> Coefficient {
            if i == 0 {
                Coefficient::MONT
            } else {
                let m = Coefficient((Coefficient::MONT.0 * 17) % Coefficient::Q);
                tmp(i - 1).mul(m)
            }
        }

        let z = tmp(reverse_bits(i, bits));
        if z.0 > Coefficient::Q / 2 {
            Coefficient(z.0 - Coefficient::Q)
        } else if z.0 < -Coefficient::Q / 2 {
            Coefficient(z.0 + Coefficient::Q)
        } else {
            z
        }
    }
}

impl Add for Coefficient {
    type Output = Coefficient;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Coefficient::barrett_reduce(self.0.wrapping_add(rhs.0))
    }
}

impl Sub for Coefficient {
    type Output = Coefficient;

    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Coefficient(self.0 - rhs.0)
    }
}

impl Mul for Coefficient {
    type Output = Coefficient;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::Coefficient;

    #[test]
    fn zetas() {
        let zetas = [
            -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202,
            -1474, 1468, 573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608,
            -1542, 411, -205, -1571, 1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8,
            -320, -666, -1618, -1162, 126, 1469, -853, -90, -271, 830, 107, -1421, -247, -951,
            -398, 961, -1508, -725, 448, -1065, 677, -1275, -1103, 430, 555, 843, -1251, 871, 1550,
            105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246, 778, 1159, -147, -777, 1483,
            -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097, 603, 610, 1322,
            -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185, -1530,
            -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
        ];
        for (i, x) in zetas.into_iter().enumerate() {
            assert_eq!(Coefficient::zeta(i, 7).0, x);
        }
    }
}
