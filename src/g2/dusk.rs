// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::{Error as BytesError, Serializable};
use subtle::{Choice, ConditionallySelectable, CtOption};

use super::{G2Affine, B};
use crate::fp::Fp;
use crate::fp2::Fp2;

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

impl G2Affine {
    /// Raw bytes representation
    ///
    /// The intended usage of this function is for trusted sets of data where performance is
    /// critical.
    ///
    /// For secure serialization, check `to_bytes`
    pub fn to_raw_bytes(&self) -> [u8; Self::RAW_SIZE] {
        let mut bytes = [0u8; Self::RAW_SIZE];
        let chunks = bytes.chunks_mut(8);

        self.x
            .c0
            .internal_repr()
            .iter()
            .chain(self.x.c1.internal_repr().iter())
            .chain(self.y.c0.internal_repr().iter())
            .chain(self.y.c1.internal_repr().iter())
            .zip(chunks)
            .for_each(|(n, c)| c.copy_from_slice(&n.to_le_bytes()));

        bytes[Self::RAW_SIZE - 1] = self.infinity.into();

        bytes
    }

    /// Create a `G2Affine` from a set of bytes created by `G2Affine::to_raw_bytes`.
    ///
    /// # Safety
    /// No check is performed and no constant time is granted. The expected
    /// usage of this function is for trusted bytes where performance is
    /// critical.
    /// For secure serialization, check `from_bytes`.
    /// After generating the point, you can check `is_on_curve` and
    /// `is_torsion_free` to grant its security.
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut xc0 = [0u64; 6];
        let mut xc1 = [0u64; 6];
        let mut yc0 = [0u64; 6];
        let mut yc1 = [0u64; 6];
        let mut z = [0u8; 8];

        xc0.iter_mut()
            .chain(xc1.iter_mut())
            .chain(yc0.iter_mut())
            .chain(yc1.iter_mut())
            .zip(bytes.chunks_exact(8))
            .for_each(|(n, c)| {
                z.copy_from_slice(c);
                *n = u64::from_le_bytes(z);
            });

        let c0 = Fp::from_raw_unchecked(xc0);
        let c1 = Fp::from_raw_unchecked(xc1);
        let x = Fp2 { c0, c1 };

        let c0 = Fp::from_raw_unchecked(yc0);
        let c1 = Fp::from_raw_unchecked(yc1);
        let y = Fp2 { c0, c1 };

        let infinity = if bytes.len() >= Self::RAW_SIZE {
            bytes[Self::RAW_SIZE - 1].into()
        } else {
            0u8.into()
        };

        Self { x, y, infinity }
    }
}

impl Serializable<96> for G2Affine {
    type Error = BytesError;

    /// Serializes this element into compressed form. See [`notes::serialization`](crate::notes::serialization)
    /// for details about how group elements are serialized.
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let infinity = self.infinity.into();

        // Strictly speaking, self.x is zero already when self.infinity is true, but
        // to guard against implementation mistakes we do not assume this.
        let x = Fp2::conditional_select(&self.x, &Fp2::zero(), infinity);

        let mut res = [0; Self::SIZE];

        (res[0..48]).copy_from_slice(&x.c1.to_bytes()[..]);
        (res[48..96]).copy_from_slice(&x.c0.to_bytes()[..]);

        // This point is in compressed form, so we set the most significant bit.
        res[0] |= 1u8 << 7;

        // Is this point at infinity? If so, set the second-most significant bit.
        res[0] |= u8::conditional_select(&0u8, &(1u8 << 6), infinity);

        // Is the y-coordinate the lexicographically largest of the two associated with the
        // x-coordinate? If so, set the third-most significant bit so long as this is not
        // the point at infinity.
        res[0] |= u8::conditional_select(
            &0u8,
            &(1u8 << 5),
            (!infinity) & self.y.lexicographically_largest(),
        );

        res
    }

    /// Attempts to deserialize a compressed element. See [`notes::serialization`](crate::notes::serialization)
    /// for details about how group elements are serialized.
    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        // We already know the point is on the curve because this is established
        // by the y-coordinate recovery procedure in from_compressed_unchecked().

        // Obtain the three flags from the start of the byte sequence
        let compression_flag_set = Choice::from((buf[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((buf[0] >> 6) & 1);
        let sort_flag_set = Choice::from((buf[0] >> 5) & 1);

        // Attempt to obtain the x-coordinate
        let xc1 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&buf[0..48]);

            // Mask away the flag bits
            tmp[0] &= 0b0001_1111;

            Fp::from_bytes(&tmp)
        };
        let xc0 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&buf[48..96]);

            Fp::from_bytes(&tmp)
        };

        let x: Option<Self> = xc1
            .and_then(|xc1| {
                xc0.and_then(|xc0| {
                    let x = Fp2 { c0: xc0, c1: xc1 };

                    // If the infinity flag is set, return the value assuming
                    // the x-coordinate is zero and the sort bit is not set.
                    //
                    // Otherwise, return a recovered point (assuming the correct
                    // y-coordinate can be found) so long as the infinity flag
                    // was not set.
                    CtOption::new(
                        G2Affine::identity(),
                        infinity_flag_set & // Infinity flag should be set
                    compression_flag_set & // Compression flag should be set
                    (!sort_flag_set) & // Sort flag should not be set
                    x.is_zero(), // The x-coordinate should be zero
                    )
                    .or_else(|| {
                        // Recover a y-coordinate given x by y = sqrt(x^3 + 4)
                        ((x.square() * x) + B).sqrt().and_then(|y| {
                            // Switch to the correct y-coordinate if necessary.
                            let y = Fp2::conditional_select(
                                &y,
                                &-y,
                                y.lexicographically_largest() ^ sort_flag_set,
                            );

                            CtOption::new(
                                G2Affine {
                                    x,
                                    y,
                                    infinity: infinity_flag_set.into(),
                                },
                                (!infinity_flag_set) & // Infinity flag should not be set
                            compression_flag_set, // Compression flag should be set
                            )
                        })
                    })
                })
            })
            .into();

        match x {
            Some(x) if x.is_torsion_free().unwrap_u8() == 1 => Ok(x),
            _ => Err(BytesError::InvalidData),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for G2Affine {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(Self::SIZE)?;
        for byte in <Self as Serializable<96>>::to_bytes(self).iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for G2Affine {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct G2AffineVisitor;

        impl<'de> Visitor<'de> for G2AffineVisitor {
            type Value = G2Affine;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a 48-byte cannonical compressed G2Affine point from Bls12_381")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<G2Affine, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; G2Affine::SIZE];
                for i in 0..G2Affine::SIZE {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or(serde::de::Error::invalid_length(i, &"expected 48 bytes"))?;
                }

                <G2Affine as Serializable<96>>::from_bytes(&bytes).map_err(|_| {
                    serde::de::Error::custom(&"compressed G2Affine was not canonically encoded")
                })
            }
        }

        deserializer.deserialize_tuple(Self::SIZE, G2AffineVisitor)
    }
}

#[test]
#[cfg(feature = "serde")]
fn g2_affine_serde_roundtrip() {
    use bincode;

    let gen = G2Affine::generator();
    let ser = bincode::serialize(&gen).unwrap();
    let deser: G2Affine = bincode::deserialize(&ser).unwrap();

    assert_eq!(gen, deser);
}

#[test]
fn g2_affine_bytes_unchecked() {
    let gen = G2Affine::generator();
    let ident = G2Affine::identity();

    let gen_p = gen.to_raw_bytes();
    let gen_p = unsafe { G2Affine::from_slice_unchecked(&gen_p) };

    let ident_p = ident.to_raw_bytes();
    let ident_p = unsafe { G2Affine::from_slice_unchecked(&ident_p) };

    assert_eq!(gen, gen_p);
    assert_eq!(ident, ident_p);
}
