//! Fixed-exponent addition chains for field arithmetic.

#[cfg(test)]
macro_rules! test_chain {
    ($field:ty, $elements:expr, $chain:path, $exponent:expr) => {
        test_chain!($field, $elements, $chain, $exponent, pow_vartime);
    };
    ($field:ty, $elements:expr, $chain:path, $exponent:expr, $reference:ident) => {{
        use rand_core::SeedableRng as _;

        for x in $elements {
            assert_eq!($chain(x), x.$reference($exponent));
        }

        let mut rng = rand_xorshift::XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        for _ in 0..32 {
            let x = <$field>::try_random(&mut rng).unwrap();
            assert_eq!($chain(&x), x.$reference($exponent));
        }
    }};
}

#[cfg(feature = "groups")]
#[macro_use]
mod p_minus3_over4;

#[cfg(feature = "groups")]
pub(crate) mod fp;
#[cfg(feature = "groups")]
pub(crate) mod fp2;
pub(crate) mod scalar;
