use alloc::string::String;

use group::Curve;
use hex_conservative::{DisplayHex, FromHex};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_big_array::BigArray;

use crate::g1::{G1Affine, G1Projective};
use crate::g2::{G2Affine, G2Projective};
use crate::scalar::Scalar;

impl Serialize for Scalar {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let byte_array = self.to_bytes();

        if s.is_human_readable() {
            s.serialize_str(&DisplayHex::to_lower_hex_string(byte_array.as_slice()))
        } else {
            Serialize::serialize(&byte_array, s)
        }
    }
}

impl<'d> Deserialize<'d> for Scalar {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let byte_array = if d.is_human_readable() {
            <[u8; 32] as FromHex>::from_hex(&<String>::deserialize(d)?)
                .map_err(serde::de::Error::custom)?
        } else {
            <[u8; 32] as Deserialize>::deserialize(d)?
        };

        let scalar = Scalar::from_bytes(&byte_array);

        if scalar.is_some().into() {
            Ok(scalar.unwrap())
        } else {
            Err(D::Error::custom("Could not decode scalar"))
        }
    }
}

impl Serialize for G1Affine {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let byte_array = self.to_compressed();

        if s.is_human_readable() {
            s.serialize_str(&DisplayHex::to_lower_hex_string(byte_array.as_slice()))
        } else {
            BigArray::serialize(&byte_array, s)
        }
    }
}

impl<'d> Deserialize<'d> for G1Affine {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let byte_array = if d.is_human_readable() {
            <[u8; 48] as FromHex>::from_hex(&<String>::deserialize(d)?)
                .map_err(serde::de::Error::custom)?
        } else {
            <[u8; 48] as BigArray<u8>>::deserialize(d)?
        };

        let g = G1Affine::from_compressed(&byte_array);

        if g.is_some().into() {
            Ok(g.unwrap())
        } else {
            Err(D::Error::custom(
                "Could not decode compressed group element",
            ))
        }
    }
}

impl Serialize for G2Affine {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let byte_array = self.to_compressed();

        if s.is_human_readable() {
            s.serialize_str(&DisplayHex::to_lower_hex_string(byte_array.as_slice()))
        } else {
            BigArray::serialize(&byte_array, s)
        }
    }
}

impl<'d> Deserialize<'d> for G2Affine {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let byte_array = if d.is_human_readable() {
            <[u8; 96] as FromHex>::from_hex(&<String>::deserialize(d)?)
                .map_err(serde::de::Error::custom)?
        } else {
            <[u8; 96] as BigArray<u8>>::deserialize(d)?
        };

        let g = G2Affine::from_compressed(&byte_array);

        if g.is_some().into() {
            Ok(g.unwrap())
        } else {
            Err(D::Error::custom(
                "Could not decode compressed group element",
            ))
        }
    }
}

impl Serialize for G1Projective {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_affine().serialize(s)
    }
}

impl<'d> Deserialize<'d> for G1Projective {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        Ok(G1Affine::deserialize(d)?.into())
    }
}

impl Serialize for G2Projective {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_affine().serialize(s)
    }
}

impl<'d> Deserialize<'d> for G2Projective {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        Ok(G2Affine::deserialize(d)?.into())
    }
}

#[test]
fn serde_json_scalar_roundtrip() {
    let serialized = serde_json::to_string(&Scalar::zero()).unwrap();

    assert_eq!(
        serialized,
        "\"0000000000000000000000000000000000000000000000000000000000000000\""
    );

    let deserialized: Scalar = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized, Scalar::zero());
}

#[test]
fn serde_json_g1_roundtrip() {
    let serialized = serde_json::to_string(&G1Affine::generator()).unwrap();

    assert_eq!(
        serialized,
        "\"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\""
    );

    let deserialized: G1Affine = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized, G1Affine::generator());
}

#[test]
fn serde_json_g2_roundtrip() {
    let serialized = serde_json::to_string(&G2Affine::generator()).unwrap();

    assert_eq!(
        serialized,
        "\"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8\""
    );

    let deserialized: G2Affine = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized, G2Affine::generator());
}
