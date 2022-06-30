//! This module implements message expansion consistent with the
//! hash-to-curve RFC drafts 7 through 16

use core::fmt::{self, Debug, Formatter};

use digest::{
    generic_array::typenum::IsLess, BlockInput, ExtendableOutput, FixedOutput, Update, XofReader,
};

use crate::generic_array::{
    typenum::{Unsigned, U256},
    ArrayLength, GenericArray,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

const MAX_DST_LENGTH: usize = 255;
const OVERSIZE_DST_SALT: &[u8] = b"H2C-OVERSIZE-DST-";

/// The domain separation tag for a message expansion.
///
/// Implements [section 5.3.3 of `draft-irtf-cfrg-hash-to-curve-16`][dst].
///
/// [dst]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3.3
#[derive(Debug)]
struct ExpandMsgDst {
    dst: [u8; MAX_DST_LENGTH],
    len: usize,
}

impl ExpandMsgDst {
    #[inline]
    fn new(init: impl FnOnce(&mut [u8; MAX_DST_LENGTH]) -> usize) -> Self {
        let mut slf = ExpandMsgDst {
            dst: [0u8; MAX_DST_LENGTH],
            len: 0,
        };
        slf.len = init(&mut slf.dst);
        assert!(slf.len <= MAX_DST_LENGTH);
        slf
    }

    /// Produces a DST for use with `expand_message_xof`.
    pub fn for_xof<H, L>(dst: &[u8]) -> Self
    where
        H: Default + Update + ExtendableOutput,
        L: ArrayLength<u8> + IsLess<U256>,
    {
        let input_len = dst.len();
        ExpandMsgDst::new(|buf| {
            if input_len > MAX_DST_LENGTH {
                H::default()
                    .chain(OVERSIZE_DST_SALT)
                    .chain(&dst)
                    .finalize_xof()
                    .read(&mut buf[..L::USIZE]);
                L::USIZE
            } else {
                buf[..input_len].copy_from_slice(dst);
                input_len
            }
        })
    }

    /// Produces a DST for use with `expand_message_xmd`.
    pub fn for_xmd<H>(dst: &[u8]) -> Self
    where
        H: Default + FixedOutput + Update,
    {
        let input_len = dst.len();
        ExpandMsgDst::new(|buf| {
            if input_len > MAX_DST_LENGTH {
                let hashed = H::default()
                    .chain(OVERSIZE_DST_SALT)
                    .chain(&dst)
                    .finalize_fixed();
                let len = hashed.len().min(MAX_DST_LENGTH);
                buf[..len].copy_from_slice(&hashed);
                len
            } else {
                buf[..input_len].copy_from_slice(dst);
                input_len
            }
        })
    }

    /// Returns the raw bytes of the DST.
    pub fn data(&self) -> &[u8] {
        &self.dst[..self.len]
    }

    /// Returns the length of the DST.
    pub fn len(&self) -> usize {
        self.len
    }
}

/// A trait allowing flexible support for message input types.
pub trait Message {
    /// Consume the message input.
    ///
    /// The parameters to successive calls to `f` are treated as a
    /// single concatenated octet string.
    fn consume(self, f: impl FnMut(&[u8]));
}

impl Message for &[u8] {
    #[inline]
    fn consume(self, mut f: impl FnMut(&[u8])) {
        f(self)
    }
}

impl<const N: usize> Message for &[u8; N] {
    #[inline]
    fn consume(self, mut f: impl FnMut(&[u8])) {
        f(self)
    }
}

impl Message for &str {
    #[inline]
    fn consume(self, mut f: impl FnMut(&[u8])) {
        f(self.as_bytes())
    }
}

impl Message for &[&[u8]] {
    #[inline]
    fn consume(self, mut f: impl FnMut(&[u8])) {
        for msg in self {
            f(msg);
        }
    }
}

#[cfg(feature = "alloc")]
impl Message for Vec<u8> {
    #[inline]
    fn consume(self, mut f: impl FnMut(&[u8])) {
        f(self.as_slice())
    }
}

#[cfg(feature = "alloc")]
impl Message for &Vec<u8> {
    #[inline]
    fn consume(self, mut f: impl FnMut(&[u8])) {
        f(self.as_slice())
    }
}

#[cfg(feature = "alloc")]
impl Message for alloc::string::String {
    #[inline]
    fn consume(self, mut f: impl FnMut(&[u8])) {
        f(self.as_bytes())
    }
}

#[cfg(feature = "alloc")]
impl Message for &alloc::string::String {
    #[inline]
    fn consume(self, mut f: impl FnMut(&[u8])) {
        f(self.as_bytes())
    }
}

/// A trait for message expansion methods supported by hash-to-curve.
pub trait ExpandMessage {
    /// Initializes a message expander.
    fn init_expand<M, L>(message: M, dst: &[u8], len_in_bytes: usize) -> Self
    where
        M: Message,
        L: ArrayLength<u8> + IsLess<U256>;

    /// Reads bytes from the generated output.
    fn read_into(&mut self, output: &mut [u8]) -> usize;

    /// Retrieves the number of bytes remaining in the generator.
    fn remain(&self) -> usize;

    #[cfg(feature = "alloc")]
    /// Constructs a `Vec` containing the remaining bytes of the output.
    fn into_vec(mut self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut result = alloc::vec![0u8; self.remain()];
        self.read_into(&mut result[..]);
        result
    }
}

/// A generator for the output of `expand_message_xof` for a given
/// extendable hash function, message, DST, and output length.
///
/// Implements [section 5.3.2 of `draft-irtf-cfrg-hash-to-curve-16`][expand_message_xof].
///
/// The length parameter L defaults to U32, corresponding to the target security level of
/// k = 128 for both defined BLS12-381 ciphersuites.
///
/// [expand_message_xof]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3.2
pub struct ExpandMsgXof<H: ExtendableOutput> {
    reader: <H as ExtendableOutput>::Reader,
    remain: usize,
}

impl<H: ExtendableOutput> Debug for ExpandMsgXof<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandMsgXof")
            .field("remain", &self.remain)
            .finish()
    }
}

impl<H> ExpandMessage for ExpandMsgXof<H>
where
    H: Default + ExtendableOutput + Update,
{
    fn init_expand<M, L>(message: M, dst: &[u8], len_in_bytes: usize) -> Self
    where
        M: Message,
        L: ArrayLength<u8> + IsLess<U256>,
    {
        if len_in_bytes > u16::MAX as usize {
            panic!("Invalid ExpandMsgXof usage: len_in_bytes > u16::MAX");
        }

        let dst = ExpandMsgDst::for_xof::<H, L>(dst);
        let mut hash = H::default();
        message.consume(|m| hash.update(m));
        let reader = hash
            .chain((len_in_bytes as u16).to_be_bytes())
            .chain(dst.data())
            .chain([dst.len() as u8])
            .finalize_xof();
        Self {
            reader,
            remain: len_in_bytes,
        }
    }

    fn read_into(&mut self, output: &mut [u8]) -> usize {
        let len = self.remain.min(output.len());
        self.reader.read(&mut output[..len]);
        self.remain -= len;
        len
    }

    fn remain(&self) -> usize {
        self.remain
    }
}

/// A generator for the output of `expand_message_xmd` for a given
/// digest hash function, message, DST, and output length.
///
/// Implements [section 5.3.1 of `draft-irtf-cfrg-hash-to-curve-16`][expand_message_xmd].
///
/// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-5.3.1
pub struct ExpandMsgXmd<H: FixedOutput> {
    dst: ExpandMsgDst,
    b_0: GenericArray<u8, H::OutputSize>,
    b_i: GenericArray<u8, H::OutputSize>,
    i: usize,
    b_offs: usize,
    remain: usize,
}

impl<H: FixedOutput> Debug for ExpandMsgXmd<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandMsgXmd")
            .field("remain", &self.remain)
            .finish()
    }
}

impl<H> ExpandMessage for ExpandMsgXmd<H>
where
    H: Default + BlockInput + FixedOutput + Update,
{
    fn init_expand<M, L>(message: M, dst: &[u8], len_in_bytes: usize) -> Self
    where
        M: Message,
        L: ArrayLength<u8> + IsLess<U256>,
    {
        let hash_size = <H as FixedOutput>::OutputSize::to_usize();
        let ell = (len_in_bytes + hash_size - 1) / hash_size;
        if ell > 255 {
            panic!("Invalid ExpandMsgXmd usage: ell > 255");
        }
        let dst = ExpandMsgDst::for_xmd::<H>(dst);
        let mut hash_b_0 =
            H::default().chain(GenericArray::<u8, <H as BlockInput>::BlockSize>::default());
        message.consume(|m| hash_b_0.update(m));
        let b_0 = hash_b_0
            .chain((len_in_bytes as u16).to_be_bytes())
            .chain([0u8])
            .chain(dst.data())
            .chain([dst.len() as u8])
            .finalize_fixed();
        // init with b_1
        let b_i = H::default()
            .chain(&b_0)
            .chain([1u8])
            .chain(dst.data())
            .chain([dst.len() as u8])
            .finalize_fixed();
        ExpandMsgXmd {
            dst,
            b_0,
            b_i,
            i: 2,
            b_offs: 0,
            remain: len_in_bytes,
        }
    }

    fn read_into(&mut self, output: &mut [u8]) -> usize {
        let read_len = self.remain.min(output.len());
        let mut offs = 0;
        let hash_size = H::OutputSize::to_usize();
        while offs < read_len {
            let b_offs = self.b_offs;
            let mut copy_len = hash_size - b_offs;
            if copy_len > 0 {
                copy_len = copy_len.min(read_len - offs);
                output[offs..(offs + copy_len)]
                    .copy_from_slice(&self.b_i[b_offs..(b_offs + copy_len)]);
                offs += copy_len;
                self.b_offs = b_offs + copy_len;
            } else {
                let mut b_prev_xor = self.b_0.clone();
                for j in 0..hash_size {
                    b_prev_xor[j] ^= self.b_i[j];
                }
                self.b_i = H::default()
                    .chain(b_prev_xor)
                    .chain([self.i as u8])
                    .chain(self.dst.data())
                    .chain([self.dst.len() as u8])
                    .finalize_fixed();
                self.b_offs = 0;
                self.i += 1;
            }
        }
        self.remain -= read_len;
        read_len
    }

    fn remain(&self) -> usize {
        self.remain
    }
}
