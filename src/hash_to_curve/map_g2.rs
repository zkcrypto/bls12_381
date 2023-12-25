//! Implementation of hash-to-curve for the G2 group

use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

use super::chain::chain_p2m9div16;
use super::{HashToField, MapToCurve, Sgn0};
use crate::generic_array::{
    typenum::{U128, U32, U64},
    GenericArray,
};
use crate::{fp::Fp, fp2::Fp2, g2::G2Projective};

/// Coefficients of the 3-isogeny x map's numerator
const ISO3_XNUM: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x47f6_71c7_1ce0_5e62,
            0x06dd_5707_1206_393e,
            0x7c80_cd2a_f3fd_71a2,
            0x0481_03ea_9e6c_d062,
            0xc545_16ac_c8d0_37f6,
            0x1380_8f55_0920_ea41,
        ]),
        c1: Fp::from_raw_unchecked([
            0x47f6_71c7_1ce0_5e62,
            0x06dd_5707_1206_393e,
            0x7c80_cd2a_f3fd_71a2,
            0x0481_03ea_9e6c_d062,
            0xc545_16ac_c8d0_37f6,
            0x1380_8f55_0920_ea41,
        ]),
    },
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0x5fe5_5555_554c_71d0,
            0x873f_ffdd_236a_aaa3,
            0x6a6b_4619_b26e_f918,
            0x21c2_8884_0887_4945,
            0x2836_cda7_028c_abc5,
            0x0ac7_3310_a7fd_5abd,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x0a0c_5555_5559_71c3,
            0xdb0c_0010_1f9e_aaae,
            0xb1fb_2f94_1d79_7997,
            0xd396_0742_ef41_6e1c,
            0xb700_40e2_c205_56f4,
            0x149d_7861_e581_393b,
        ]),
        c1: Fp::from_raw_unchecked([
            0xaff2_aaaa_aaa6_38e8,
            0x439f_ffee_91b5_5551,
            0xb535_a30c_d937_7c8c,
            0x90e1_4442_0443_a4a2,
            0x941b_66d3_8146_55e2,
            0x0563_9988_53fe_ad5e,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x40aa_c71c_71c7_25ed,
            0x1909_5555_7a84_e38e,
            0xd817_050a_8f41_abc3,
            0xd864_85d4_c87f_6fb1,
            0x696e_b479_f885_d059,
            0x198e_1a74_3280_02d2,
        ]),
        c1: Fp::zero(),
    },
];

/// Coefficients of the 3-isogeny x map's denominator
const ISO3_XDEN: [Fp2; 3] = [
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0x1f3a_ffff_ff13_ab97,
            0xf25b_fc61_1da3_ff3e,
            0xca37_57cb_3819_b208,
            0x3e64_2736_6f8c_ec18,
            0x0397_7bc8_6095_b089,
            0x04f6_9db1_3f39_a952,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x4476_0000_0027_552e,
            0xdcb8_009a_4348_0020,
            0x6f7e_e9ce_4a6e_8b59,
            0xb103_30b7_c0a9_5bc6,
            0x6140_b1fc_fb1e_54b7,
            0x0381_be09_7f0b_b4e1,
        ]),
        c1: Fp::from_raw_unchecked([
            0x7588_ffff_ffd8_557d,
            0x41f3_ff64_6e0b_ffdf,
            0xf7b1_e8d2_ac42_6aca,
            0xb374_1acd_32db_b6f8,
            0xe9da_f5b9_482d_581f,
            0x167f_53e0_ba74_31b8,
        ]),
    },
    Fp2::one(),
];

/// Coefficients of the 3-isogeny y map's numerator
const ISO3_YNUM: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x96d8_f684_bdfc_77be,
            0xb530_e4f4_3b66_d0e2,
            0x184a_88ff_3796_52fd,
            0x57cb_23ec_fae8_04e1,
            0x0fd2_e39e_ada3_eba9,
            0x08c8_055e_31c5_d5c3,
        ]),
        c1: Fp::from_raw_unchecked([
            0x96d8_f684_bdfc_77be,
            0xb530_e4f4_3b66_d0e2,
            0x184a_88ff_3796_52fd,
            0x57cb_23ec_fae8_04e1,
            0x0fd2_e39e_ada3_eba9,
            0x08c8_055e_31c5_d5c3,
        ]),
    },
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0xbf0a_71c7_1c91_b406,
            0x4d6d_55d2_8b76_38fd,
            0x9d82_f98e_5f20_5aee,
            0xa27a_a27b_1d1a_18d5,
            0x02c3_b2b2_d293_8e86,
            0x0c7d_1342_0b09_807f,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0xd7f9_5555_5553_1c74,
            0x21cf_fff7_48da_aaa8,
            0x5a9a_d186_6c9b_be46,
            0x4870_a221_0221_d251,
            0x4a0d_b369_c0a3_2af1,
            0x02b1_ccc4_29ff_56af,
        ]),
        c1: Fp::from_raw_unchecked([
            0xe205_aaaa_aaac_8e37,
            0xfcdc_0007_6879_5556,
            0x0c96_011a_8a15_37dd,
            0x1c06_a963_f163_406e,
            0x010d_f44c_82a8_81e6,
            0x174f_4526_0f80_8feb,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0xa470_bda1_2f67_f35c,
            0xc0fe_38e2_3327_b425,
            0xc9d3_d0f2_c6f0_678d,
            0x1c55_c993_5b5a_982e,
            0x27f6_c0e2_f074_6764,
            0x117c_5e6e_28aa_9054,
        ]),
        c1: Fp::zero(),
    },
];

/// Coefficients of the 3-isogeny y map's denominator
const ISO3_YDEN: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x0162_ffff_fa76_5adf,
            0x8f7b_ea48_0083_fb75,
            0x561b_3c22_59e9_3611,
            0x11e1_9fc1_a9c8_75d5,
            0xca71_3efc_0036_7660,
            0x03c6_a03d_41da_1151,
        ]),
        c1: Fp::from_raw_unchecked([
            0x0162_ffff_fa76_5adf,
            0x8f7b_ea48_0083_fb75,
            0x561b_3c22_59e9_3611,
            0x11e1_9fc1_a9c8_75d5,
            0xca71_3efc_0036_7660,
            0x03c6_a03d_41da_1151,
        ]),
    },
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0x5db0_ffff_fd3b_02c5,
            0xd713_f523_58eb_fdba,
            0x5ea6_0761_a84d_161a,
            0xbb2c_75a3_4ea6_c44a,
            0x0ac6_7359_21c1_119b,
            0x0ee3_d913_bdac_fbf6,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x66b1_0000_003a_ffc5,
            0xcb14_00e7_64ec_0030,
            0xa73e_5eb5_6fa5_d106,
            0x8984_c913_a0fe_09a9,
            0x11e1_0afb_78ad_7f13,
            0x0542_9d0e_3e91_8f52,
        ]),
        c1: Fp::from_raw_unchecked([
            0x534d_ffff_ffc4_aae6,
            0x5397_ff17_4c67_ffcf,
            0xbff2_73eb_870b_251d,
            0xdaf2_8271_5287_0915,
            0x393a_9cba_ca9e_2dc3,
            0x14be_74db_faee_5748,
        ]),
    },
    Fp2::one(),
];

const SSWU_ELLP_A: Fp2 = Fp2 {
    c0: Fp::zero(),
    c1: Fp::from_raw_unchecked([
        0xe53a_0000_0313_5242,
        0x0108_0c0f_def8_0285,
        0xe788_9edb_e340_f6bd,
        0x0b51_3751_2631_0601,
        0x02d6_9857_17c7_44ab,
        0x1220_b4e9_79ea_5467,
    ]),
};

const SSWU_ELLP_B: Fp2 = Fp2 {
    c0: Fp::from_raw_unchecked([
        0x22ea_0000_0cf8_9db2,
        0x6ec8_32df_7138_0aa4,
        0x6e1b_9440_3db5_a66e,
        0x75bf_3c53_a794_73ba,
        0x3dd3_a569_412c_0a34,
        0x125c_db5e_74dc_4fd1,
    ]),
    c1: Fp::from_raw_unchecked([
        0x22ea_0000_0cf8_9db2,
        0x6ec8_32df_7138_0aa4,
        0x6e1b_9440_3db5_a66e,
        0x75bf_3c53_a794_73ba,
        0x3dd3_a569_412c_0a34,
        0x125c_db5e_74dc_4fd1,
    ]),
};

const SSWU_XI: Fp2 = Fp2 {
    c0: Fp::from_raw_unchecked([
        0x87eb_ffff_fff9_555c,
        0x656f_ffe5_da8f_fffa,
        0x0fd0_7493_45d3_3ad2,
        0xd951_e663_0665_76f4,
        0xde29_1a3d_41e9_80d3,
        0x0815_664c_7dfe_040d,
    ]),
    c1: Fp::from_raw_unchecked([
        0x43f5_ffff_fffc_aaae,
        0x32b7_fff2_ed47_fffd,
        0x07e8_3a49_a2e9_9d69,
        0xeca8_f331_8332_bb7a,
        0xef14_8d1e_a0f4_c069,
        0x040a_b326_3eff_0206,
    ]),
};

const SSWU_ETAS: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x05e5_1466_8ac7_36d2,
            0x9089_b4d6_b84f_3ea5,
            0x603c_384c_224a_8b32,
            0xf325_7909_536a_fea6,
            0x5c5c_dbab_ae65_6d81,
            0x075b_fa08_63c9_87e9,
        ]),
        c1: Fp::from_raw_unchecked([
            0x338d_9bfe_0808_7330,
            0x7b8e_48b2_bd83_cefe,
            0x530d_ad5d_306b_5be7,
            0x5a4d_7e8e_6c40_8b6d,
            0x6258_f7a6_232c_ab9b,
            0x0b98_5811_cce1_4db5,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x8671_6401_f7f7_377b,
            0xa31d_b74b_f3d0_3101,
            0x1423_2543_c645_9a3c,
            0x0a29_ccf6_8744_8752,
            0xe8c2_b010_201f_013c,
            0x0e68_b9d8_6c9e_98e4,
        ]),
        c1: Fp::from_raw_unchecked([
            0x05e5_1466_8ac7_36d2,
            0x9089_b4d6_b84f_3ea5,
            0x603c_384c_224a_8b32,
            0xf325_7909_536a_fea6,
            0x5c5c_dbab_ae65_6d81,
            0x075b_fa08_63c9_87e9,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x718f_dad2_4ee1_d90f,
            0xa58c_025b_ed82_76af,
            0x0c3a_1023_0ab7_976f,
            0xf0c5_4df5_c8f2_75e1,
            0x4ec2_478c_28ba_f465,
            0x1129_373a_90c5_08e6,
        ]),
        c1: Fp::from_raw_unchecked([
            0x019a_f5f9_80a3_680c,
            0x4ed7_da0e_6606_3afa,
            0x6003_5472_3b5d_9972,
            0x8b2f_958b_20d0_9d72,
            0x0474_938f_02d4_61db,
            0x0dcf_8b9e_0684_ab1c,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0xb864_0a06_7f5c_429f,
            0xcfd4_25f0_4b4d_c505,
            0x072d_7e2e_bb53_5cb1,
            0xd947_b5f9_d2b4_754d,
            0x46a7_1427_4077_4afb,
            0x0c31_864c_32fb_3b7e,
        ]),
        c1: Fp::from_raw_unchecked([
            0x718f_dad2_4ee1_d90f,
            0xa58c_025b_ed82_76af,
            0x0c3a_1023_0ab7_976f,
            0xf0c5_4df5_c8f2_75e1,
            0x4ec2_478c_28ba_f465,
            0x1129_373a_90c5_08e6,
        ]),
    },
];

const SSWU_RV1: Fp2 = Fp2 {
    c0: Fp::from_raw_unchecked([
        0x7bcf_a7a2_5aa3_0fda,
        0xdc17_dec1_2a92_7e7c,
        0x2f08_8dd8_6b4e_bef1,
        0xd1ca_2087_da74_d4a7,
        0x2da2_5966_96ce_bc1d,
        0x0e2b_7eed_bbfd_87d2,
    ]),
    c1: Fp::from_raw_unchecked([
        0x7bcf_a7a2_5aa3_0fda,
        0xdc17_dec1_2a92_7e7c,
        0x2f08_8dd8_6b4e_bef1,
        0xd1ca_2087_da74_d4a7,
        0x2da2_5966_96ce_bc1d,
        0x0e2b_7eed_bbfd_87d2,
    ]),
};

impl HashToField for Fp2 {
    // ceil(log2(p)) = 381, m = 2, k = 128.
    type InputLength = U128;

    // k = 128
    type XofOutputLength = U32;

    fn from_okm(okm: &GenericArray<u8, U128>) -> Fp2 {
        let c0 = <Fp as HashToField>::from_okm(GenericArray::<u8, U64>::from_slice(&okm[..64]));
        let c1 = <Fp as HashToField>::from_okm(GenericArray::<u8, U64>::from_slice(&okm[64..]));
        Fp2 { c0, c1 }
    }
}

impl Sgn0 for Fp2 {
    fn sgn0(&self) -> Choice {
        let sign_0 = self.c0.sgn0();
        let zero_0 = self.c0.is_zero();
        let sign_1 = self.c1.sgn0();
        sign_0 | (zero_0 & sign_1)
    }
}

/// Maps from an [`Fp2]` element to a point on iso-G2.
fn map_to_curve_simple_swu(u: &Fp2) -> G2Projective {
    let usq = u.square();
    let xi_usq = SSWU_XI * usq;
    let xisq_u4 = xi_usq.square();
    let nd_common = xisq_u4 + xi_usq; // XI^2 * u^4 + XI * u^2
    let x_den = SSWU_ELLP_A * Fp2::conditional_select(&(-nd_common), &SSWU_XI, nd_common.is_zero());
    let x0_num = SSWU_ELLP_B * (Fp2::one() + nd_common); // B * (1 + (XI^2 * u^4 + XI * u^2))

    // compute g(x0(u))
    let x_densq = x_den.square();
    let gx_den = x_densq * x_den;
    // x0_num^3 + A * x0_num * x_den^2 + B * x_den^3
    let gx0_num = (x0_num.square() + SSWU_ELLP_A * x_densq) * x0_num + SSWU_ELLP_B * gx_den;

    // compute g(x0(u)) ^ ((p^2 - 9) // 16)
    let sqrt_candidate = {
        let vsq = gx_den.square(); // v^2
        let v_3 = vsq * gx_den; // v^3
        let v_4 = vsq.square(); // v^4
        let uv_7 = gx0_num * v_3 * v_4; // u v^7
        let uv_15 = uv_7 * v_4.square(); // u v^15
        uv_7 * chain_p2m9div16(&uv_15) // u v^7 (u v^15) ^ ((p^2 - 9) // 16)
    };

    // set y = sqrt_candidate * Fp2::one(), check candidate against other roots of unity
    let mut y = sqrt_candidate;
    // check Fp2(0, 1)
    let tmp = Fp2 {
        c0: -sqrt_candidate.c1,
        c1: sqrt_candidate.c0,
    };
    y.conditional_assign(&tmp, (tmp.square() * gx_den).ct_eq(&gx0_num));
    // check Fp2(RV1, RV1)
    let tmp = sqrt_candidate * SSWU_RV1;
    y.conditional_assign(&tmp, (tmp.square() * gx_den).ct_eq(&gx0_num));
    // check Fp2(RV1, -RV1)
    let tmp = Fp2 {
        c0: tmp.c1,
        c1: -tmp.c0,
    };
    y.conditional_assign(&tmp, (tmp.square() * gx_den).ct_eq(&gx0_num));

    // compute g(x1(u)) = g(x0(u)) * XI^3 * u^6
    let gx1_num = gx0_num * xi_usq * xisq_u4;
    // compute g(x1(u)) * u^3
    let sqrt_candidate = sqrt_candidate * usq * u;
    let mut eta_found = Choice::from(0u8);
    for eta in &SSWU_ETAS[..] {
        let tmp = sqrt_candidate * eta;
        let found = (tmp.square() * gx_den).ct_eq(&gx1_num);
        y.conditional_assign(&tmp, found);
        eta_found |= found;
    }

    let x_num = Fp2::conditional_select(&x0_num, &(x0_num * xi_usq), eta_found);
    // ensure sign of y and sign of u agree
    y.conditional_negate(u.sgn0() ^ y.sgn0());

    G2Projective {
        x: x_num,
        y: y * x_den,
        z: x_den,
    }
}

/// Maps from an iso-G2 point to a G2 point.
fn iso_map(u: &G2Projective) -> G2Projective {
    const COEFFS: [&[Fp2]; 4] = [&ISO3_XNUM, &ISO3_XDEN, &ISO3_YNUM, &ISO3_YDEN];

    // unpack input point
    let G2Projective { x, y, z } = *u;

    // xnum, xden, ynum, yden
    let mut mapvals = [Fp2::zero(); 4];

    // compute powers of z
    let zsq = z.square();
    let zpows = [z, zsq, zsq * z];

    // compute map value by Horner's rule
    for idx in 0..4 {
        let coeff = COEFFS[idx];
        let clast = coeff.len() - 1;
        mapvals[idx] = coeff[clast];
        for jdx in 0..clast {
            mapvals[idx] = mapvals[idx] * x + zpows[jdx] * coeff[clast - 1 - jdx];
        }
    }

    // x denominator is order 1 less than x numerator, so we need an extra factor of z
    mapvals[1] *= z;

    // multiply result of Y map by the y-coord, y / z
    mapvals[2] *= y;
    mapvals[3] *= z;

    G2Projective {
        x: mapvals[0] * mapvals[3], // xnum * yden,
        y: mapvals[2] * mapvals[1], // ynum * xden,
        z: mapvals[1] * mapvals[3], // xden * yden
    }
}

impl MapToCurve for G2Projective {
    type Field = Fp2;

    fn map_to_curve(u: &Fp2) -> G2Projective {
        let pt = map_to_curve_simple_swu(u);
        iso_map(&pt)
    }

    fn clear_h(&self) -> Self {
        self.clear_cofactor()
    }
}

#[cfg(test)]
fn check_g2_prime(pt: &G2Projective) -> bool {
    // (X : Y : Z)==(X/Z, Y/Z) is on E': y^2 = x^3 + A * x + B.
    // y^2 z = (x^3) + A (x z^2) + B z^3
    let zsq = pt.z.square();
    (pt.y.square() * pt.z)
        == (pt.x.square() * pt.x + SSWU_ELLP_A * pt.x * zsq + SSWU_ELLP_B * zsq * pt.z)
}

#[test]
fn test_osswu_semirandom() {
    use rand_core::SeedableRng;
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    for _ in 0..32 {
        let input = Fp2::random(&mut rng);
        let p = map_to_curve_simple_swu(&input);
        assert!(check_g2_prime(&p));

        let p_iso = iso_map(&p);
        assert!(bool::from(p_iso.is_on_curve()));
    }
}

#[test]
fn test_sgn0() {
    use super::map_g1::P_M1_OVER2;

    assert_eq!(bool::from(Fp2::zero().sgn0()), false);
    assert_eq!(bool::from(Fp2::one().sgn0()), true);
    assert_eq!(
        bool::from(
            Fp2 {
                c0: P_M1_OVER2,
                c1: Fp::zero()
            }
            .sgn0()
        ),
        true
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: P_M1_OVER2,
                c1: Fp::one()
            }
            .sgn0()
        ),
        true
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: Fp::zero(),
                c1: P_M1_OVER2,
            }
            .sgn0()
        ),
        true
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: Fp::one(),
                c1: P_M1_OVER2,
            }
            .sgn0()
        ),
        true
    );

    let p_p1_over2 = P_M1_OVER2 + Fp::one();
    assert_eq!(
        bool::from(
            Fp2 {
                c0: p_p1_over2,
                c1: Fp::zero()
            }
            .sgn0()
        ),
        false
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: p_p1_over2,
                c1: Fp::one()
            }
            .sgn0()
        ),
        false
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: Fp::zero(),
                c1: p_p1_over2,
            }
            .sgn0()
        ),
        false
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: Fp::one(),
                c1: p_p1_over2,
            }
            .sgn0()
        ),
        true
    );

    assert_eq!(
        bool::from(
            Fp2 {
                c0: P_M1_OVER2,
                c1: -Fp::one()
            }
            .sgn0()
        ),
        true
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: p_p1_over2,
                c1: -Fp::one()
            }
            .sgn0()
        ),
        false
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: Fp::zero(),
                c1: -Fp::one()
            }
            .sgn0()
        ),
        false
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: P_M1_OVER2,
                c1: p_p1_over2
            }
            .sgn0()
        ),
        true
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: p_p1_over2,
                c1: P_M1_OVER2
            }
            .sgn0()
        ),
        false
    );

    assert_eq!(
        bool::from(
            Fp2 {
                c0: -Fp::one(),
                c1: P_M1_OVER2,
            }
            .sgn0()
        ),
        false
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: -Fp::one(),
                c1: p_p1_over2,
            }
            .sgn0()
        ),
        false
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: -Fp::one(),
                c1: Fp::zero(),
            }
            .sgn0()
        ),
        false
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: p_p1_over2,
                c1: P_M1_OVER2,
            }
            .sgn0()
        ),
        false
    );
    assert_eq!(
        bool::from(
            Fp2 {
                c0: P_M1_OVER2,
                c1: p_p1_over2,
            }
            .sgn0()
        ),
        true
    );
}
