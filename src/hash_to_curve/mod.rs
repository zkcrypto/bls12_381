//! This module implements hash_to_curve, hash_to_field and related
//! hashing primitives for use with BLS signatures.

use core::ops::Add;

pub(crate) mod chain;

mod expand_msg;
pub use self::expand_msg::{ExpandMessage, ExpandMsgXmd, ExpandMsgXof, InitExpandMessage};

mod map_g1;
mod map_g2;

use crate::generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

/// Convert from hashed key material to a field element for a given curve
pub trait HashToField {
    /// The length of the data used to produce a field element
    type InputLength: ArrayLength<u8>;
    /// The field element type
    type Pt: Copy + Default;

    /// Convert output keying material to a field element
    fn input_okm(okm: &GenericArray<u8, Self::InputLength>) -> Self::Pt;
}

/// Allow conversion from the output of hashed or encoded input into points on the curve
pub trait MapToCurve: HashToField {
    /// Map an element of the finite field to a point on the curve E
    fn map_to_curve_simple_ssw(pt: &Self::Pt) -> Self;

    /// Clear the cofactor, sending a point on curve E to the target group (G1/G2)
    fn clear_h(&self) -> Self;
}

/// Implementation of random oracle maps to the curve
pub trait HashToCurve<'x, X>
where
    X: InitExpandMessage<'x>,
{
    /// Uniformly random encoding
    fn hash_to_curve(msg: impl AsRef<[u8]>, dst: &'x [u8]) -> Self;

    /// Non-uniformly random encoding
    fn encode_to_curve(msg: impl AsRef<[u8]>, dst: &'x [u8]) -> Self;
}

impl<'x, F, X> HashToCurve<'x, X> for F
where
    F: MapToCurve + for<'a> Add<&'a Self, Output = Self>,
    X: InitExpandMessage<'x>,
{
    fn hash_to_curve(message: impl AsRef<[u8]>, dst: &'x [u8]) -> F {
        let mut u = [F::Pt::default(); 2];
        hash_to_field::<F, X>(message.as_ref(), dst, &mut u);
        // Note: draft 7 suggested adding the two outputs of map_to_curve_simple_ssw
        // and performing iso_map on the result. This suggestion is removed in draft 8,
        // but the outputs should be consistent between the two methods.
        let p1 = F::map_to_curve_simple_ssw(&u[0]);
        let p2 = F::map_to_curve_simple_ssw(&u[1]);
        (p1 + &p2).clear_h()
    }

    fn encode_to_curve(message: impl AsRef<[u8]>, dst: &'x [u8]) -> F {
        let mut u = [F::Pt::default(); 1];
        hash_to_field::<F, X>(message.as_ref(), dst, &mut u);
        let p = F::map_to_curve_simple_ssw(&u[0]);
        p.clear_h()
    }
}

/// Hash to field for the type `F` using ExpandMessage variant `X`.
pub fn hash_to_field<'x, F, X>(message: &[u8], dst: &'x [u8], output: &mut [<F as HashToField>::Pt])
where
    F: HashToField,
    X: InitExpandMessage<'x>,
{
    let len_per_elm = F::InputLength::to_usize();
    let len_in_bytes = output.len() * len_per_elm;
    let mut expander = X::init_expand(message, dst, len_in_bytes);

    let mut buf = GenericArray::<u8, F::InputLength>::default();
    for idx in 0..output.len() {
        expander.read_into(&mut buf[..]);
        output[idx] = F::input_okm(&buf);
    }
}
