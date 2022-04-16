use core::{
    mem::MaybeUninit,
    slice::{self, SliceIndex},
    ops::{Index, IndexMut},
};

#[derive(Clone, Copy)]
pub struct Array<T, const N: usize>([MaybeUninit<T>; N])
where
    T: Copy;

impl<T, const N: usize> Array<T, N>
where
    T: Copy,
{
    #[inline]
    pub fn initialize(array: [MaybeUninit<T>; N]) -> Self {
        Array(array)
    }

    #[inline]
    pub fn new<I>(it: &mut I) -> Self
    where
        I: Iterator<Item = T>,
    {
        let mut s = Array(unsafe { MaybeUninit::uninit().assume_init() });
        let mut c = N;
        for (i, x) in it.enumerate().take(N) {
            s.0[i] = MaybeUninit::new(x);
            c -= 1;
        }
        assert_eq!(c, 0, "iterator is too short to initialize {N} items");
        s
    }
}

impl<T, const N: usize> FromIterator<T> for Array<T, N>
where
    T: Copy,
{
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        Self::new(&mut iter.into_iter())
    }
}

impl<T, const N: usize> AsRef<[T]> for Array<T, N>
where
    T: Copy,
{
    #[inline]
    fn as_ref(&self) -> &[T] {
        unsafe { slice::from_raw_parts(self.0[0].as_ptr(), N) }
    }
}

impl<T, const N: usize> AsMut<[T]> for Array<T, N>
where
    T: Copy,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        unsafe { slice::from_raw_parts_mut(self.0[0].as_mut_ptr(), N) }
    }
}

impl<S, T, const N: usize> Index<S> for Array<T, N>
where
    T: Copy,
    S: SliceIndex<[T]>,
{
    type Output = S::Output;

    #[inline]
    fn index(&self, index: S) -> &Self::Output {
        &self.as_ref()[index]
    }
}

impl<S, T, const N: usize> IndexMut<S> for Array<T, N>
where
    T: Copy,
    S: SliceIndex<[T]>,
{
    #[inline]
    fn index_mut(&mut self, index: S) -> &mut Self::Output {
        &mut self.as_mut()[index]
    }
}

impl<T, const N: usize> PartialEq for Array<T, N>
where
    T: Copy + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        let mut i = 0;
        while i < N {
            if self[i].ne(&other[i]) {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl<T, const N: usize> Eq for Array<T, N> where T: Copy + PartialEq {}
