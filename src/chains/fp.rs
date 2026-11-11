use crate::fp::Fp;

#[inline(always)]
fn sqr_n(x: Fp, n: usize) -> Fp {
    (0..n).fold(x, |x, _| x.square())
}

#[cfg(feature = "experimental")]
impl_pow_by_p_minus3_over4!(Fp);

#[cfg(test)]
mod tests {
    #[cfg(feature = "experimental")]
    use rand_core::SeedableRng;

    use super::*;
    use crate::fp::Fp;

    #[cfg(feature = "experimental")]
    const P_MINUS3_OVER4: [u64; 6] = [
        0xee7f_bfff_ffff_eaaa,
        0x07aa_ffff_ac54_ffff,
        0xd9cc_34a8_3dac_3d89,
        0xd91d_d2e1_3ce1_44af,
        0x92c6_e9ed_90d2_eb35,
        0x0680_447a_8e5f_f9a6,
    ];

    #[cfg(feature = "experimental")]
    #[test]
    fn test_pow_by_p_minus3_over4() {
        const SEED: [u8; 16] = [
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ];
        let mut rng = rand_xorshift::XorShiftRng::from_seed(SEED);
        for x in [Fp::zero(), Fp::one(), -Fp::one()] {
            assert_eq!(pow_by_p_minus3_over4(&x), x.pow_vartime(&P_MINUS3_OVER4));
        }
        for _ in 0..32 {
            let x = Fp::try_random(&mut rng).unwrap();
            assert_eq!(pow_by_p_minus3_over4(&x), x.pow_vartime(&P_MINUS3_OVER4));
        }
    }
}
