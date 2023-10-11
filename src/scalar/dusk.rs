// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::cmp::{Ord, Ordering, PartialOrd};
use core::convert::TryFrom;
use core::ops::{BitAnd, BitXor};
use dusk_bytes::{Error as BytesError, Serializable};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::{Scalar, MODULUS, R2};
use crate::util::sbb;

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

impl PartialOrd for Scalar {
    fn partial_cmp(&self, other: &Scalar) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Scalar {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            #[allow(clippy::comparison_chain)]
            if self.0[i] > other.0[i] {
                return Ordering::Greater;
            } else if self.0[i] < other.0[i] {
                return Ordering::Less;
            }
        }
        Ordering::Equal
    }
}

impl Serializable<32> for Scalar {
    type Error = BytesError;

    /// Converts an element of `Scalar` into a byte representation in
    /// little-endian byte order.
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        // Turn into canonical form by computing
        // (a.R) / R = a
        let tmp = Scalar::montgomery_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0);

        let mut res = [0; Self::SIZE];
        res[0..8].copy_from_slice(&tmp.0[0].to_le_bytes());
        res[8..16].copy_from_slice(&tmp.0[1].to_le_bytes());
        res[16..24].copy_from_slice(&tmp.0[2].to_le_bytes());
        res[24..32].copy_from_slice(&tmp.0[3].to_le_bytes());

        res
    }

    /// Attempts to convert a little-endian byte representation of
    /// a scalar into a `Scalar`, failing if the input is not canonical.
    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut s = [0u64; 4];

        s.iter_mut()
            .zip(buf.chunks_exact(8))
            .try_for_each(|(s, b)| {
                <[u8; 8]>::try_from(b)
                    .map(|b| *s = u64::from_le_bytes(b))
                    .map_err(|_| BytesError::InvalidData)
            })?;

        // Try to subtract the modulus
        let (_, borrow) = sbb(s[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb(s[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb(s[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(s[3], MODULUS.0[3], borrow);

        // If the element is smaller than MODULUS then the
        // subtraction will underflow, producing a borrow value
        // of 0xffff...ffff. Otherwise, it'll be zero.
        if (borrow as u8) & 1 != 1 {
            return Err(BytesError::InvalidData);
        }

        let mut s = Scalar(s);

        // Convert to Montgomery form by computing
        // (a.R^0 * R^2) / R = a.R
        s *= &R2;

        Ok(s)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(Self::SIZE)?;
        for byte in self.to_bytes().iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ScalarVisitor;

        impl<'de> Visitor<'de> for ScalarVisitor {
            type Value = Scalar;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a 32-byte canonical Scalar from Bls12_381")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Scalar, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; Scalar::SIZE];

                for i in 0..Scalar::SIZE {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or(serde::de::Error::invalid_length(i, &"expected 32 bytes"))?;
                }

                <Scalar as Serializable<32>>::from_bytes(&bytes)
                    .map_err(|_| serde::de::Error::custom(&"scalar was not canonically encoded"))
            }
        }

        deserializer.deserialize_tuple(Self::SIZE, ScalarVisitor)
    }
}

#[allow(dead_code)]
pub const GEN_X: Scalar = Scalar([
    0x1539098E9CBCC1D5,
    0x0CCC77B0E1804E8D,
    0x6EEF947A6FD0FB2C,
    0xA3D063F54E10DDE9,
]);

#[allow(dead_code)]
pub const GEN_Y: Scalar = Scalar([
    0x6540D21E7007DC60,
    0x3B0D848E832A862F,
    0xB53BB87E05DA8257,
    0xCD482CC3FD6FF4D,
]);

impl<'a, 'b> BitXor<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    fn bitxor(self, rhs: &'b Scalar) -> Scalar {
        let a_red = self.reduce();
        let b_red = rhs.reduce();
        Scalar::from_raw([
            a_red.0[0] ^ b_red.0[0],
            a_red.0[1] ^ b_red.0[1],
            a_red.0[2] ^ b_red.0[2],
            a_red.0[3] ^ b_red.0[3],
        ])
    }
}

impl BitXor<Scalar> for Scalar {
    type Output = Scalar;

    fn bitxor(self, rhs: Scalar) -> Scalar {
        &self ^ &rhs
    }
}

impl BitAnd<Scalar> for Scalar {
    type Output = Scalar;

    fn bitand(self, rhs: Scalar) -> Scalar {
        &self & &rhs
    }
}

impl<'a, 'b> BitAnd<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    fn bitand(self, rhs: &'b Scalar) -> Scalar {
        let a_red = self.reduce();
        let b_red = rhs.reduce();
        Scalar::from_raw([
            a_red.0[0] & b_red.0[0],
            a_red.0[1] & b_red.0[1],
            a_red.0[2] & b_red.0[2],
            a_red.0[3] & b_red.0[3],
        ])
    }
}

impl Scalar {
    /// Checks in ct_time whether a Scalar is equal to zero.
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Scalar::zero())
    }

    /// Checks in ct_time whether a Scalar is equal to one.   
    pub fn is_one(&self) -> Choice {
        self.ct_eq(&Scalar::one())
    }

    /// Returns the internal representation of the Scalar.
    pub const fn internal_repr(&self) -> &[u64; 4] {
        &self.0
    }

    /// Returns the bit representation of the given `Scalar` as
    /// an array of 256 bits represented as `u8`.
    pub fn to_bits(&self) -> [u8; 256] {
        let mut res = [0u8; 256];
        let bytes = self.to_bytes();
        for (byte, bits) in bytes.iter().zip(res.chunks_mut(8)) {
            bits.iter_mut()
                .enumerate()
                .for_each(|(i, bit)| *bit = (byte >> i) & 1)
        }
        res
    }

    /// Reduces the scalar and returns it multiplied by the montgomery
    /// radix.
    pub fn reduce(&self) -> Scalar {
        Scalar::montgomery_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0)
    }

    /// Computes `2^X` where X is a `u64` without the need to generate
    /// an array in the stack as `pow` & `pow_vartime` require.
    pub fn pow_of_2(by: u64) -> Self {
        let two = Scalar::from(2u64);
        let mut res = Self::one();
        for i in (0..64).rev() {
            res = res.square();
            let mut tmp = res;
            tmp *= two;
            res.conditional_assign(&tmp, (((by >> i) & 0x1) as u8).into());
        }
        res
    }

    /// SHR impl
    #[inline]
    pub fn divn(&mut self, mut n: u32) {
        if n >= 256 {
            *self = Self::from(0);
            return;
        }

        while n >= 64 {
            let mut t = 0;
            for i in self.0.iter_mut().rev() {
                core::mem::swap(&mut t, i);
            }
            n -= 64;
        }

        if n > 0 {
            let mut t = 0;
            for i in self.0.iter_mut().rev() {
                let t2 = *i << (64 - n);
                *i >>= n;
                *i |= t;
                t = t2;
            }
        }
    }
}

#[test]
fn test_partial_ord() {
    let one = Scalar::one();
    assert!(one < -one);
}

#[test]
fn test_xor() {
    let a = Scalar::from(500u64);
    let b = Scalar::from(499u64);
    let res = Scalar::from(7u64);
    assert_eq!(&a ^ &b, res);
}

#[test]
fn test_and() {
    let a = Scalar::one();
    let b = Scalar::one();
    let res = Scalar::one();
    assert_eq!(&a & &b, res);
    assert_eq!(a & -a, Scalar::zero());
}

#[test]
fn test_iter_sum() {
    let scalars = vec![Scalar::one(), Scalar::one()];
    let res: Scalar = scalars.iter().sum();
    assert_eq!(res, Scalar::one() + Scalar::one());
}

#[test]
fn test_iter_prod() {
    let scalars = vec![Scalar::one() + Scalar::one(), Scalar::one() + Scalar::one()];
    let res: Scalar = scalars.iter().product();
    assert_eq!(res, Scalar::from(4u64));
}

#[test]
#[cfg(feature = "serde")]
fn serde_bincode_scalar_roundtrip() {
    use bincode;
    let scalar = -Scalar::from(3u64);
    let encoded = bincode::serialize(&scalar).unwrap();
    let parsed: Scalar = bincode::deserialize(&encoded).unwrap();
    assert_eq!(parsed, scalar);

    // Check that the encoding is 32 bytes exactly
    assert_eq!(encoded.len(), 32);

    // Check that the encoding itself matches the usual one
    assert_eq!(scalar, bincode::deserialize(&scalar.to_bytes()).unwrap(),);
}

#[test]
fn bit_repr() {
    let two_pow_128 = Scalar::from(2u64).pow(&[128, 0, 0, 0]);
    let two_pow_128_bits = [
        0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(&two_pow_128.to_bits()[..], &two_pow_128_bits[..]);

    let two_pow_128_minus_rand = Scalar::from(2u64).pow(&[128, 0, 0, 0]) - Scalar::from(7568589u64);
    let two_pow_128_bits = [
        1u8, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1,
    ];
    assert_eq!(
        &two_pow_128_minus_rand.to_bits()[..128],
        &two_pow_128_bits[..]
    )
}

#[test]
fn pow_of_two_test() {
    let two = Scalar::from(2u64);
    for i in 0..1000 {
        assert_eq!(Scalar::pow_of_2(i as u64), two.pow(&[i as u64, 0, 0, 0]));
    }
}
