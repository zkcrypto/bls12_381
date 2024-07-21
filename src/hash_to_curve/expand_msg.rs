//! This module implements message expansion consistent with the
//! hash-to-curve RFC drafts 7 through 10

use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use digest::{BlockInput, Digest, ExtendableOutputDirty, Update, XofReader};

use crate::generic_array::{
    typenum::{Unsigned, U32},
    ArrayLength, GenericArray,
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

const OVERSIZE_DST_SALT: &[u8] = b"H2C-OVERSIZE-DST-";

/// The domain separation tag for a message expansion.
///
/// Implements [section 5.4.3 of `draft-irtf-cfrg-hash-to-curve-12`][dst].
///
/// [dst]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.3
#[derive(Debug)]
enum ExpandMsgDst<'x, L: ArrayLength<u8>> {
    /// DST produced by hashing a very long (> 255 chars) input DST.
    Hashed(GenericArray<u8, L>),
    /// A raw input DST (<= 255 chars).
    Raw(&'x [u8]),
}

impl<'x, L: ArrayLength<u8>> ExpandMsgDst<'x, L> {
    /// Produces a DST for use with `expand_message_xof`.
    pub fn process_xof<H>(dst: &'x [u8]) -> Self
    where
        H: Default + Update + ExtendableOutputDirty,
    {
        if dst.len() > 255 {
            let mut data = GenericArray::<u8, L>::default();
            H::default()
                .chain(OVERSIZE_DST_SALT)
                .chain(&dst)
                .finalize_xof_dirty()
                .read(&mut data);
            Self::Hashed(data)
        } else {
            Self::Raw(dst)
        }
    }

    /// Produces a DST for use with `expand_message_xmd`.
    pub fn process_xmd<H>(dst: &'x [u8]) -> Self
    where
        H: Digest<OutputSize = L>,
    {
        if dst.len() > 255 {
            Self::Hashed(H::new().chain(OVERSIZE_DST_SALT).chain(&dst).finalize())
        } else {
            Self::Raw(dst)
        }
    }

    /// Returns the raw bytes of the DST.
    pub fn data(&'x self) -> &'x [u8] {
        match self {
            Self::Hashed(arr) => &arr[..],
            Self::Raw(buf) => buf,
        }
    }

    /// Returns the length of the DST.
    pub fn len(&'x self) -> usize {
        match self {
            Self::Hashed(_) => L::to_usize(),
            Self::Raw(buf) => buf.len(),
        }
    }
}

/// A trait for message expansion methods supported by hash-to-curve.
pub trait ExpandMessage: for<'x> InitExpandMessage<'x> {
    // This intermediate is likely only necessary until GATs allow
    // associated types with lifetimes.
}

/// Trait for constructing a new message expander.
pub trait InitExpandMessage<'x> {
    /// The state object used during message expansion.
    type Expander: ExpandMessageState<'x>;

    /// Initializes a message expander.
    fn init_expand(message: &[u8], dst: &'x [u8], len_in_bytes: usize) -> Self::Expander;
}

// Automatically derive trait
impl<X: for<'x> InitExpandMessage<'x>> ExpandMessage for X {}

/// Trait for types implementing the `expand_message` interface for `hash_to_field`.
pub trait ExpandMessageState<'x> {
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
/// Implements [section 5.4.2 of `draft-irtf-cfrg-hash-to-curve-12`][expand_message_xof]
/// with `k = 128`.
///
/// [expand_message_xof]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.2
pub struct ExpandMsgXof<H: ExtendableOutputDirty> {
    hash: <H as ExtendableOutputDirty>::Reader,
    remain: usize,
}

impl<H: ExtendableOutputDirty> Debug for ExpandMsgXof<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandMsgXof")
            .field("remain", &self.remain)
            .finish()
    }
}

impl<'x, H> ExpandMessageState<'x> for ExpandMsgXof<H>
where
    H: ExtendableOutputDirty,
{
    fn read_into(&mut self, output: &mut [u8]) -> usize {
        let len = self.remain.min(output.len());
        self.hash.read(&mut output[..len]);
        self.remain -= len;
        len
    }

    fn remain(&self) -> usize {
        self.remain
    }
}

impl<'x, H> InitExpandMessage<'x> for ExpandMsgXof<H>
where
    H: Default + Update + ExtendableOutputDirty,
{
    type Expander = Self;

    fn init_expand(message: &[u8], dst: &[u8], len_in_bytes: usize) -> Self {
        // Use U32 here for k = 128.
        let dst = ExpandMsgDst::<U32>::process_xof::<H>(dst);
        let hash = H::default()
            .chain(message)
            .chain((len_in_bytes as u16).to_be_bytes())
            .chain(dst.data())
            .chain([dst.len() as u8])
            .finalize_xof_dirty();
        Self {
            hash,
            remain: len_in_bytes,
        }
    }
}

/// Constructor for `expand_message_xmd` for a given digest hash function, message, DST,
/// and output length.
///
/// Implements [section 5.4.1 of `draft-irtf-cfrg-hash-to-curve-12`][expand_message_xmd].
///
/// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.1
#[derive(Debug)]
pub struct ExpandMsgXmd<H: Digest>(PhantomData<H>);

/// A generator for the output of `expand_message_xmd` for a given
/// digest hash function, message, DST, and output length.
///
/// Implements [section 5.4.1 of `draft-irtf-cfrg-hash-to-curve-12`][expand_message_xmd].
///
/// [expand_message_xmd]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#section-5.4.1
pub struct ExpandMsgXmdState<'x, H: Digest> {
    dst: ExpandMsgDst<'x, H::OutputSize>,
    b_0: GenericArray<u8, H::OutputSize>,
    b_i: GenericArray<u8, H::OutputSize>,
    i: usize,
    b_offs: usize,
    remain: usize,
}

impl<H: Digest> Debug for ExpandMsgXmdState<'_, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpandMsgXmdState")
            .field("remain", &self.remain)
            .finish()
    }
}

impl<'x, H> InitExpandMessage<'x> for ExpandMsgXmd<H>
where
    H: Digest + BlockInput,
{
    type Expander = ExpandMsgXmdState<'x, H>;

    fn init_expand(message: &[u8], dst: &'x [u8], len_in_bytes: usize) -> Self::Expander {
        let hash_size = <H as Digest>::OutputSize::to_usize();
        let ell = (len_in_bytes + hash_size - 1) / hash_size;
        if ell > 255 {
            panic!("Invalid ExpandMsgXmd usage: ell > 255");
        }
        let dst = ExpandMsgDst::process_xmd::<H>(dst);
        let b_0 = H::new()
            .chain(GenericArray::<u8, <H as BlockInput>::BlockSize>::default())
            .chain(message)
            .chain((len_in_bytes as u16).to_be_bytes())
            .chain([0u8])
            .chain(dst.data())
            .chain([dst.len() as u8])
            .finalize();
        // init with b_1
        let b_i = H::new()
            .chain(&b_0)
            .chain([1u8])
            .chain(dst.data())
            .chain([dst.len() as u8])
            .finalize();
        ExpandMsgXmdState {
            dst,
            b_0,
            b_i,
            i: 2,
            b_offs: 0,
            remain: len_in_bytes,
        }
    }
}

impl<'x, H> ExpandMessageState<'x> for ExpandMsgXmdState<'x, H>
where
    H: Digest + BlockInput,
{
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
                self.b_i = H::new()
                    .chain(b_prev_xor)
                    .chain([self.i as u8])
                    .chain(self.dst.data())
                    .chain([self.dst.len() as u8])
                    .finalize();
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
