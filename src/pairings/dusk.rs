// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::fp::Fp;
use crate::fp2::Fp2;

use super::G2Prepared;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{
    self, de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer,
};
#[cfg(feature = "serde")]
use subtle::Choice;

#[cfg(feature = "alloc")]
impl G2Prepared {
    /// Raw bytes representation
    ///
    /// The intended usage of this function is for trusted sets of data
    /// where performance is critical. This way, the `infinity` internal
    /// attribute will not be stored and the coefficients will be stored
    /// without any check.
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        let mut bytes = alloc::vec![0u8; 288 * self.coeffs.len()];
        let mut chunks = bytes.chunks_exact_mut(8);

        self.coeffs.iter().for_each(|(a, b, c)| {
            a.c0.internal_repr()
                .iter()
                .chain(a.c1.internal_repr().iter())
                .chain(b.c0.internal_repr().iter())
                .chain(b.c1.internal_repr().iter())
                .chain(c.c0.internal_repr().iter())
                .chain(c.c1.internal_repr().iter())
                .for_each(|n| {
                    if let Some(c) = chunks.next() {
                        c.copy_from_slice(&n.to_le_bytes())
                    }
                })
        });

        bytes
    }

    /// Create a `G2Prepared` from a set of bytes created by
    /// `G2Prepared::to_raw_bytes`.
    ///
    /// No check is performed and no constant time is granted. The
    /// `infinity` attribute is also lost. The expected usage of this
    /// function is for trusted bytes where performance is critical.
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let coeffs = bytes
            .chunks_exact(288)
            .map(|c| {
                let mut ac0 = [0u64; 6];
                let mut ac1 = [0u64; 6];
                let mut bc0 = [0u64; 6];
                let mut bc1 = [0u64; 6];
                let mut cc0 = [0u64; 6];
                let mut cc1 = [0u64; 6];
                let mut z = [0u8; 8];

                ac0.iter_mut()
                    .chain(ac1.iter_mut())
                    .chain(bc0.iter_mut())
                    .chain(bc1.iter_mut())
                    .chain(cc0.iter_mut())
                    .chain(cc1.iter_mut())
                    .zip(c.chunks_exact(8))
                    .for_each(|(n, c)| {
                        z.copy_from_slice(c);
                        *n = u64::from_le_bytes(z);
                    });

                let c0 = Fp::from_raw_unchecked(ac0);
                let c1 = Fp::from_raw_unchecked(ac1);
                let a = Fp2 { c0, c1 };

                let c0 = Fp::from_raw_unchecked(bc0);
                let c1 = Fp::from_raw_unchecked(bc1);
                let b = Fp2 { c0, c1 };

                let c0 = Fp::from_raw_unchecked(cc0);
                let c1 = Fp::from_raw_unchecked(cc1);
                let c = Fp2 { c0, c1 };

                (a, b, c)
            })
            .collect();
        let infinity = 0u8.into();

        Self { coeffs, infinity }
    }
}

#[cfg(feature = "serde")]
impl Serialize for G2Prepared {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut g2_prepared = serializer.serialize_struct("struct G2Prepared", 2)?;
        // We encode the choice as an u8 field.
        g2_prepared.serialize_field("choice", &self.infinity.unwrap_u8())?;
        // Since we have serde support for `Fp2` we can treat the `Vec` as a
        // regular field.
        g2_prepared.serialize_field("coeffs", &self.coeffs)?;
        g2_prepared.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for G2Prepared {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Choice,
            Coeffs,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter,
                    ) -> ::core::fmt::Result {
                        formatter.write_str("struct G2Prepared")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "choice" => Ok(Field::Choice),
                            "coeffs" => Ok(Field::Coeffs),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct G2PreparedVisitor;

        impl<'de> Visitor<'de> for G2PreparedVisitor {
            type Value = G2Prepared;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct G2Prepared")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<G2Prepared, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let choice_as_u8: u8 = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let coeffs = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let choice: Choice = Choice::from(choice_as_u8);
                Ok(G2Prepared {
                    infinity: choice.into(),
                    coeffs,
                })
            }
        }

        const FIELDS: &[&str] = &["choice", "coeffs"];
        deserializer.deserialize_struct("G2Prepared", FIELDS, G2PreparedVisitor)
    }
}

#[test]
#[cfg(feature = "serde")]
fn g2_prepared_serde_roundtrip() {
    use crate::G2Affine;
    use bincode;

    let g2_prepared = G2Prepared::from(G2Affine::generator());
    let ser = bincode::serialize(&g2_prepared).unwrap();
    let deser: G2Prepared = bincode::deserialize(&ser).unwrap();

    assert_eq!(g2_prepared.coeffs, deser.coeffs);
    assert_eq!(g2_prepared.infinity.unwrap_u8(), deser.infinity.unwrap_u8())
}

#[test]
fn g2_prepared_bytes_unchecked() {
    use crate::G2Affine;

    let g2_prepared = G2Prepared::from(G2Affine::generator());
    let bytes = g2_prepared.to_raw_bytes();

    let g2_prepared_p = unsafe { G2Prepared::from_slice_unchecked(&bytes) };

    assert_eq!(g2_prepared.coeffs, g2_prepared_p.coeffs);
}
