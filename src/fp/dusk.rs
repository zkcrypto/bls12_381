// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::Fp;

impl Fp {
    /// Internal representation of `Fp`
    pub const fn internal_repr(&self) -> &[u64; 6] {
        &self.0
    }
}

#[cfg(feature = "serde")]
use serde::{
    self, de::Visitor, ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer,
};

#[cfg(feature = "serde")]
impl Serialize for Fp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tup = serializer.serialize_seq(Some(48))?;
        let fp_as_bytes = self.to_bytes();
        for i in 0..48 {
            tup.serialize_element(&fp_as_bytes[i])?;
        }
        tup.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Fp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FpVisitor;

        impl<'de> Visitor<'de> for FpVisitor {
            type Value = Fp;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a prover key with valid powers per points")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Fp, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 48];
                for i in 0..48 {
                    bytes[i] = seq
                        .next_element()?
                        .ok_or(serde::de::Error::invalid_length(i, &"expected 48 bytes"))?;
                }
                let res = Fp::from_bytes(&bytes);
                if res.is_some().unwrap_u8() == 1u8 {
                    return Ok(res.unwrap());
                } else {
                    return Err(serde::de::Error::custom(&"fp was not canonically encoded"));
                }
            }
        }

        deserializer.deserialize_seq(FpVisitor)
    }
}

#[test]
#[cfg(feature = "serde")]
fn fp_serde_roundtrip() {
    use bincode;
    let fp = Fp::one();
    let ser = bincode::serialize(&fp).unwrap();
    let deser: Fp = bincode::deserialize(&ser).unwrap();

    assert_eq!(fp, deser);
}
