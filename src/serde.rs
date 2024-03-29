use group::Curve;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::g1::{G1Affine, G1Projective};
use crate::g2::{G2Affine, G2Projective};
use crate::scalar::Scalar;

impl Serialize for Scalar {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.to_bytes(), s)
    }
}

impl<'d> Deserialize<'d> for Scalar {
    fn deserialize<D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
        let mut byte_array = [0; 32];

        serdect::array::deserialize_hex_or_bin(&mut byte_array, d)?;

        Option::from(Scalar::from_bytes(&byte_array))
            .ok_or_else(|| D::Error::custom("Could not decode scalar"))
    }
}

impl Serialize for G1Affine {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.to_compressed(), s)
    }
}

impl<'d> Deserialize<'d> for G1Affine {
    fn deserialize<D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
        let mut byte_array = [0; 48];

        serdect::array::deserialize_hex_or_bin(&mut byte_array, d)?;

        Option::from(G1Affine::from_compressed(&byte_array))
            .ok_or_else(|| D::Error::custom("Could not decode compressed group element"))
    }
}

impl Serialize for G2Affine {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serdect::array::serialize_hex_lower_or_bin(&self.to_compressed(), s)
    }
}

impl<'d> Deserialize<'d> for G2Affine {
    fn deserialize<D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
        let mut byte_array = [0; 96];

        serdect::array::deserialize_hex_or_bin(&mut byte_array, d)?;

        Option::from(G2Affine::from_compressed(&byte_array))
            .ok_or_else(|| D::Error::custom("Could not decode compressed group element"))
    }
}

impl Serialize for G1Projective {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_affine().serialize(s)
    }
}

impl<'d> Deserialize<'d> for G1Projective {
    fn deserialize<D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
        Ok(G1Affine::deserialize(d)?.into())
    }
}

impl Serialize for G2Projective {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_affine().serialize(s)
    }
}

impl<'d> Deserialize<'d> for G2Projective {
    fn deserialize<D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
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
