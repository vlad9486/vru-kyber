use sha3::digest::{Update, XofReader, ExtendableOutput};

pub struct Buf<R> {
    xof: R,
    remain: Option<u16>,
}

impl<R> Buf<R>
where
    R: XofReader,
{
    pub fn new<D>(seed: &[u8; 32], i: usize, j: usize) -> Self
    where
        D: Default + Update + ExtendableOutput<Reader = R>,
    {
        Buf {
            xof: D::default()
                .chain(seed)
                .chain(&[i as u8, j as u8])
                .finalize_xof(),
            remain: None,
        }
    }
}

impl<R> Iterator for Buf<R>
where
    R: XofReader,
{
    type Item = i16;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let it = self.remain.take().unwrap_or_else(|| {
            let mut buf = [0; 3];
            self.xof.read(&mut buf);
            let v = (u16::from(buf[0]) | u16::from(buf[1]) << 8) & 0xFFF;
            self.remain = Some((u16::from(buf[1] >> 4) | u16::from(buf[2]) << 4) & 0xFFF);
            v
        });
        Some(it as i16)
    }
}
