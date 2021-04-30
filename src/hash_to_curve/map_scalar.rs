//! Implementation of hash-to-field for Scalar values

use super::HashToField;
use crate::generic_array::{typenum::U48, GenericArray};
use crate::scalar::Scalar;

impl HashToField for Scalar {
    type InputLength = U48;
    type Pt = Self;

    fn from_okm(okm: &GenericArray<u8, U48>) -> Scalar {
        const F_2_192: Scalar = Scalar::from_raw([0, 0, 0, 1]);

        let mut bs = [0u8; 32];
        bs[8..32].copy_from_slice(&okm[0..24]);
        bs.reverse(); // into little endian
        let db = Scalar::from_bytes(&bs).unwrap();

        bs[0..8].copy_from_slice(&[0u8; 8]);
        bs[8..32].copy_from_slice(&okm[24..48]);
        bs.reverse(); // into little endian
        let da = Scalar::from_bytes(&bs).unwrap();

        db * F_2_192 + da
    }
}

#[test]
fn test_hash_to_scalar() {
    let tests: &[(&[u8], &str)] = &[
        (
            &[0u8; 48],
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            b"aaaaaabbbbbbccccccddddddeeeeeeffffffgggggghhhhhh",
            "0x2228450bf55d8fe62395161bd3677ff6fc28e45b89bc87e02a818eda11a8c5da",
        ),
        (
            b"111111222222333333444444555555666666777777888888",
            "0x4aa543cbd2f0c8f37f8a375ce2e383eb343e7e3405f61e438b0a15fb8899d1ae",
        ),
    ];
    for (input, expected) in tests {
        let output = format!("{:?}", Scalar::from_okm(GenericArray::from_slice(input)));
        assert_eq!(&output, expected);
    }
}
