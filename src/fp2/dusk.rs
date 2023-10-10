// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::Fp2;

use serde::{
    self, de::Visitor, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer,
};

impl Serialize for Fp2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut fp2 = serializer.serialize_struct("struct Fp2", 2)?;
        fp2.serialize_field("c0", &self.c0)?;
        fp2.serialize_field("c1", &self.c1)?;
        fp2.end()
    }
}

impl<'de> Deserialize<'de> for Fp2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            C0,
            C1,
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
                        formatter.write_str("struct Fp2")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "c0" => Ok(Field::C0),
                            "c1" => Ok(Field::C1),
                            _ => Err(serde::de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct Fp2Visitor;

        impl<'de> Visitor<'de> for Fp2Visitor {
            type Value = Fp2;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("struct Fp2")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Fp2, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let c0 = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let c1 = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(Fp2 { c0, c1 })
            }
        }

        const FIELDS: &[&str] = &["c0", "c1"];
        deserializer.deserialize_struct("Fp2", FIELDS, Fp2Visitor)
    }
}

#[test]
fn fp2_serde_roundtrip() {
    use crate::fp::Fp;
    use bincode;

    let fp2 = Fp2 {
        c0: Fp::one(),
        c1: Fp::one(),
    };

    let ser = bincode::serialize(&fp2).unwrap();
    let deser: Fp2 = bincode::deserialize(&ser).unwrap();

    assert_eq!(fp2, deser);
}
