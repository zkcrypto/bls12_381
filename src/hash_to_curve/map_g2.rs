//! Implementation of hash-to-curve for the G2 group

use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

use super::chain::chain_p2m9div16;
use super::{HashToField, MapToCurve};
use crate::{fp::Fp, fp2::Fp2, g2::G2Projective};
use crate::{
    generic_array::{
        typenum::{U128, U64},
        GenericArray,
    },
    G1Projective,
};

/// Coefficients of the 3-isogeny x map's numerator
const ISO3_XNUM: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x47f671c71ce05e62,
            0x06dd57071206393e,
            0x7c80cd2af3fd71a2,
            0x048103ea9e6cd062,
            0xc54516acc8d037f6,
            0x13808f550920ea41,
        ]),
        c1: Fp::from_raw_unchecked([
            0x47f671c71ce05e62,
            0x06dd57071206393e,
            0x7c80cd2af3fd71a2,
            0x048103ea9e6cd062,
            0xc54516acc8d037f6,
            0x13808f550920ea41,
        ]),
    },
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0x5fe55555554c71d0,
            0x873fffdd236aaaa3,
            0x6a6b4619b26ef918,
            0x21c2888408874945,
            0x2836cda7028cabc5,
            0x0ac73310a7fd5abd,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x0a0c5555555971c3,
            0xdb0c00101f9eaaae,
            0xb1fb2f941d797997,
            0xd3960742ef416e1c,
            0xb70040e2c20556f4,
            0x149d7861e581393b,
        ]),
        c1: Fp::from_raw_unchecked([
            0xaff2aaaaaaa638e8,
            0x439fffee91b55551,
            0xb535a30cd9377c8c,
            0x90e144420443a4a2,
            0x941b66d3814655e2,
            0x0563998853fead5e,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x40aac71c71c725ed,
            0x190955557a84e38e,
            0xd817050a8f41abc3,
            0xd86485d4c87f6fb1,
            0x696eb479f885d059,
            0x198e1a74328002d2,
        ]),
        c1: Fp::zero(),
    },
];

/// Coefficients of the 3-isogeny x map's denominator
const ISO3_XDEN: [Fp2; 3] = [
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0x1f3affffff13ab97,
            0xf25bfc611da3ff3e,
            0xca3757cb3819b208,
            0x3e6427366f8cec18,
            0x03977bc86095b089,
            0x04f69db13f39a952,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x447600000027552e,
            0xdcb8009a43480020,
            0x6f7ee9ce4a6e8b59,
            0xb10330b7c0a95bc6,
            0x6140b1fcfb1e54b7,
            0x0381be097f0bb4e1,
        ]),
        c1: Fp::from_raw_unchecked([
            0x7588ffffffd8557d,
            0x41f3ff646e0bffdf,
            0xf7b1e8d2ac426aca,
            0xb3741acd32dbb6f8,
            0xe9daf5b9482d581f,
            0x167f53e0ba7431b8,
        ]),
    },
    Fp2::one(),
];

/// Coefficients of the 3-isogeny y map's numerator
const ISO3_YNUM: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x96d8f684bdfc77be,
            0xb530e4f43b66d0e2,
            0x184a88ff379652fd,
            0x57cb23ecfae804e1,
            0x0fd2e39eada3eba9,
            0x08c8055e31c5d5c3,
        ]),
        c1: Fp::from_raw_unchecked([
            0x96d8f684bdfc77be,
            0xb530e4f43b66d0e2,
            0x184a88ff379652fd,
            0x57cb23ecfae804e1,
            0x0fd2e39eada3eba9,
            0x08c8055e31c5d5c3,
        ]),
    },
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0xbf0a71c71c91b406,
            0x4d6d55d28b7638fd,
            0x9d82f98e5f205aee,
            0xa27aa27b1d1a18d5,
            0x02c3b2b2d2938e86,
            0x0c7d13420b09807f,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0xd7f9555555531c74,
            0x21cffff748daaaa8,
            0x5a9ad1866c9bbe46,
            0x4870a2210221d251,
            0x4a0db369c0a32af1,
            0x02b1ccc429ff56af,
        ]),
        c1: Fp::from_raw_unchecked([
            0xe205aaaaaaac8e37,
            0xfcdc000768795556,
            0x0c96011a8a1537dd,
            0x1c06a963f163406e,
            0x010df44c82a881e6,
            0x174f45260f808feb,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0xa470bda12f67f35c,
            0xc0fe38e23327b425,
            0xc9d3d0f2c6f0678d,
            0x1c55c9935b5a982e,
            0x27f6c0e2f0746764,
            0x117c5e6e28aa9054,
        ]),
        c1: Fp::zero(),
    },
];

/// Coefficients of the 3-isogeny y map's denominator
const ISO3_YDEN: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x0162fffffa765adf,
            0x8f7bea480083fb75,
            0x561b3c2259e93611,
            0x11e19fc1a9c875d5,
            0xca713efc00367660,
            0x03c6a03d41da1151,
        ]),
        c1: Fp::from_raw_unchecked([
            0x0162fffffa765adf,
            0x8f7bea480083fb75,
            0x561b3c2259e93611,
            0x11e19fc1a9c875d5,
            0xca713efc00367660,
            0x03c6a03d41da1151,
        ]),
    },
    Fp2 {
        c0: Fp::zero(),
        c1: Fp::from_raw_unchecked([
            0x5db0fffffd3b02c5,
            0xd713f52358ebfdba,
            0x5ea60761a84d161a,
            0xbb2c75a34ea6c44a,
            0x0ac6735921c1119b,
            0x0ee3d913bdacfbf6,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x66b10000003affc5,
            0xcb1400e764ec0030,
            0xa73e5eb56fa5d106,
            0x8984c913a0fe09a9,
            0x11e10afb78ad7f13,
            0x05429d0e3e918f52,
        ]),
        c1: Fp::from_raw_unchecked([
            0x534dffffffc4aae6,
            0x5397ff174c67ffcf,
            0xbff273eb870b251d,
            0xdaf2827152870915,
            0x393a9cbaca9e2dc3,
            0x14be74dbfaee5748,
        ]),
    },
    Fp2::one(),
];

const SSWU_ELLP_A: Fp2 = Fp2 {
    c0: Fp::zero(),
    c1: Fp::from_raw_unchecked([
        0xe53a000003135242,
        0x01080c0fdef80285,
        0xe7889edbe340f6bd,
        0x0b51375126310601,
        0x02d6985717c744ab,
        0x1220b4e979ea5467,
    ]),
};

const SSWU_ELLP_B: Fp2 = Fp2 {
    c0: Fp::from_raw_unchecked([
        0x22ea00000cf89db2,
        0x6ec832df71380aa4,
        0x6e1b94403db5a66e,
        0x75bf3c53a79473ba,
        0x3dd3a569412c0a34,
        0x125cdb5e74dc4fd1,
    ]),
    c1: Fp::from_raw_unchecked([
        0x22ea00000cf89db2,
        0x6ec832df71380aa4,
        0x6e1b94403db5a66e,
        0x75bf3c53a79473ba,
        0x3dd3a569412c0a34,
        0x125cdb5e74dc4fd1,
    ]),
};

const SSWU_XI: Fp2 = Fp2 {
    c0: Fp::from_raw_unchecked([
        0x87ebfffffff9555c,
        0x656fffe5da8ffffa,
        0x0fd0749345d33ad2,
        0xd951e663066576f4,
        0xde291a3d41e980d3,
        0x0815664c7dfe040d,
    ]),
    c1: Fp::from_raw_unchecked([
        0x43f5fffffffcaaae,
        0x32b7fff2ed47fffd,
        0x07e83a49a2e99d69,
        0xeca8f3318332bb7a,
        0xef148d1ea0f4c069,
        0x040ab3263eff0206,
    ]),
};

const SSWU_ETAS: [Fp2; 4] = [
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x05e514668ac736d2,
            0x9089b4d6b84f3ea5,
            0x603c384c224a8b32,
            0xf3257909536afea6,
            0x5c5cdbabae656d81,
            0x075bfa0863c987e9,
        ]),
        c1: Fp::from_raw_unchecked([
            0x338d9bfe08087330,
            0x7b8e48b2bd83cefe,
            0x530dad5d306b5be7,
            0x5a4d7e8e6c408b6d,
            0x6258f7a6232cab9b,
            0x0b985811cce14db5,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x86716401f7f7377b,
            0xa31db74bf3d03101,
            0x14232543c6459a3c,
            0x0a29ccf687448752,
            0xe8c2b010201f013c,
            0x0e68b9d86c9e98e4,
        ]),
        c1: Fp::from_raw_unchecked([
            0x05e514668ac736d2,
            0x9089b4d6b84f3ea5,
            0x603c384c224a8b32,
            0xf3257909536afea6,
            0x5c5cdbabae656d81,
            0x075bfa0863c987e9,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0x718fdad24ee1d90f,
            0xa58c025bed8276af,
            0x0c3a10230ab7976f,
            0xf0c54df5c8f275e1,
            0x4ec2478c28baf465,
            0x1129373a90c508e6,
        ]),
        c1: Fp::from_raw_unchecked([
            0x019af5f980a3680c,
            0x4ed7da0e66063afa,
            0x600354723b5d9972,
            0x8b2f958b20d09d72,
            0x0474938f02d461db,
            0x0dcf8b9e0684ab1c,
        ]),
    },
    Fp2 {
        c0: Fp::from_raw_unchecked([
            0xb8640a067f5c429f,
            0xcfd425f04b4dc505,
            0x072d7e2ebb535cb1,
            0xd947b5f9d2b4754d,
            0x46a7142740774afb,
            0x0c31864c32fb3b7e,
        ]),
        c1: Fp::from_raw_unchecked([
            0x718fdad24ee1d90f,
            0xa58c025bed8276af,
            0x0c3a10230ab7976f,
            0xf0c54df5c8f275e1,
            0x4ec2478c28baf465,
            0x1129373a90c508e6,
        ]),
    },
];

const SSWU_RV1: Fp2 = Fp2 {
    c0: Fp::from_raw_unchecked([
        0x7bcfa7a25aa30fda,
        0xdc17dec12a927e7c,
        0x2f088dd86b4ebef1,
        0xd1ca2087da74d4a7,
        0x2da2596696cebc1d,
        0x0e2b7eedbbfd87d2,
    ]),
    c1: Fp::from_raw_unchecked([
        0x7bcfa7a25aa30fda,
        0xdc17dec12a927e7c,
        0x2f088dd86b4ebef1,
        0xd1ca2087da74d4a7,
        0x2da2596696cebc1d,
        0x0e2b7eedbbfd87d2,
    ]),
};

impl HashToField for G2Projective {
    type InputLength = U128;
    type Pt = Fp2;

    fn input_okm(okm: &GenericArray<u8, U128>) -> Fp2 {
        let c0 = <G1Projective as HashToField>::input_okm(GenericArray::<u8, U64>::from_slice(
            &okm[..64],
        ));
        let c1 = <G1Projective as HashToField>::input_okm(GenericArray::<u8, U64>::from_slice(
            &okm[64..],
        ));
        Fp2 { c0, c1 }
    }
}

/// Map from a field element to a point on the curve E-prime
fn map_to_curve_simple_ssw(u: &Fp2) -> G2Projective {
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
    y.conditional_negate(u.sgn0() ^ y.sgn0()); // fix sign of y

    G2Projective {
        x: x_num,
        y: y * x_den,
        z: x_den,
    }
}

/// Map from a point on the curve E-prime to curve E
fn iso_map(u: &G2Projective) -> G2Projective {
    const COEFFS: [&[Fp2]; 4] = [&ISO3_XNUM, &ISO3_XDEN, &ISO3_YNUM, &ISO3_YDEN];

    // xnum, xden, ynum, yden
    let mut mapvals = [Fp2::zero(); 4];

    // unpack input point
    let G2Projective { x, y, z } = *u;

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

    // projective coordinates of resulting point
    G2Projective {
        x: mapvals[0] * mapvals[3], // xnum * yden,
        y: mapvals[2] * mapvals[1], // ynum * xden,
        z: mapvals[1] * mapvals[3], // xden * yden
    }
}

impl MapToCurve for G2Projective {
    fn map_to_curve_simple_ssw(u: &Fp2) -> G2Projective {
        let pt = map_to_curve_simple_ssw(u);
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
        let p = map_to_curve_simple_ssw(&input);
        assert!(check_g2_prime(&p));

        let p_iso = iso_map(&p);
        assert!(bool::from(p_iso.is_on_curve()));
    }
}

#[test]
fn test_encode_to_curve_07() {
    use crate::{
        g2::G2Affine,
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
    };
    use std::string::{String, ToString};

    struct TestCase {
        msg: &'static [u8],
        expected: [&'static str; 4],
    }
    impl TestCase {
        fn expected(&self) -> String {
            self.expected[0].to_string() + self.expected[1] + self.expected[2] + self.expected[3]
        }
    }

    const DOMAIN: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_NU_TESTGEN";

    let cases = vec![
        TestCase {
            msg: b"",
            expected: [
                "0d4333b77becbf9f9dfa3ca928002233d1ecc854b1447e5a71f751c9042d000f42db91c1d6649a5e0ad22bd7bf7398b8",
                "027e4bfada0b47f9f07e04aec463c7371e68f2fd0c738cd517932ea3801a35acf09db018deda57387b0f270f7a219e4d",
                "0cc76dc777ea0d447e02a41004f37a0a7b1fafb6746884e8d9fc276716ccf47e4e0899548a2ec71c2bdf1a2a50e876db",
                "053674cba9ef516ddc218fedb37324e6c47de27f88ab7ef123b006127d738293c0277187f7e2f80a299a24d84ed03da7",
            ],
        },
        TestCase {
            msg: b"abc",
            expected: [
                "18f0f87b40af67c056915dbaf48534c592524e82c1c2b50c3734d02c0172c80df780a60b5683759298a3303c5d942778",
                "09349f1cb5b2e55489dcd45a38545343451cc30a1681c57acd4fb0a6db125f8352c09f4a67eb7d1d8242cb7d3405f97b",
                "10a2ba341bc689ab947b7941ce6ef39be17acaab067bd32bd652b471ab0792c53a2bd03bdac47f96aaafe96e441f63c0",
                "02f2d9deb2c7742512f5b8230bf0fd83ea42279d7d39779543c1a43b61c885982b611f6a7a24b514995e8a098496b811",
            ],
        },
        TestCase {
            msg: b"abcdef0123456789",
            expected: [
                "19808ec5930a53c7cf5912ccce1cc33f1b3dcff24a53ce1cc4cba41fd6996dbed4843ccdd2eaf6a0cd801e562718d163",
                "149fe43777d34f0d25430dea463889bd9393bdfb4932946db23671727081c629ebb98a89604f3433fba1c67d356a4af7",
                "04783e391c30c83f805ca271e353582fdf19d159f6a4c39b73acbb637a9b8ac820cfbe2738d683368a7c07ad020e3e33",
                "04c0d6793a766233b2982087b5f4a254f261003ccb3262ea7c50903eecef3e871d1502c293f9e063d7d293f6384f4551",
            ]
        },
        TestCase {
            msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expected: [
                "0b8e0094c886487870372eb6264613a6a087c7eb9804fab789be4e47a57b29eb19b1983a51165a1b5eb025865e9fc63a",
                "0804152cbf8474669ad7d1796ab92d7ca21f32d8bed70898a748ed4e4e0ec557069003732fc86866d938538a2ae95552",
                "14c80f068ece15a3936bb00c3c883966f75b4e8d9ddde809c11f781ab92d23a2d1d103ad48f6f3bb158bf3e3a4063449",
                "09e5c8242dd7281ad32c03fe4af3f19167770016255fb25ad9b67ec51d62fade31a1af101e8f6172ec2ee8857662be3a",
            ]
        }
    ];

    for case in cases {
        let g = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
            &case.msg, DOMAIN,
        );
        let g_uncompressed = G2Affine::from(g).to_uncompressed();

        assert_eq!(case.expected(), hex::encode(&g_uncompressed[..]));
    }
}

#[test]
fn test_encode_to_curve_10() {
    use crate::{
        g2::G2Affine,
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
    };
    use std::string::{String, ToString};

    struct TestCase {
        msg: &'static [u8],
        expected: [&'static str; 4],
    }
    impl TestCase {
        fn expected(&self) -> String {
            self.expected[0].to_string() + self.expected[1] + self.expected[2] + self.expected[3]
        }
    }

    const DOMAIN: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_NU_";

    let cases = vec![
        TestCase {
            msg: b"",
            expected: [
                "126b855e9e69b1f691f816e48ac6977664d24d99f8724868a184186469ddfd4617367e94527d4b74fc86413483afb35b",
                "00e7f4568a82b4b7dc1f14c6aaa055edf51502319c723c4dc2688c7fe5944c213f510328082396515734b6612c4e7bb7",
                "1498aadcf7ae2b345243e281ae076df6de84455d766ab6fcdaad71fab60abb2e8b980a440043cd305db09d283c895e3d",
                "0caead0fd7b6176c01436833c79d305c78be307da5f6af6c133c47311def6ff1e0babf57a0fb5539fce7ee12407b0a42",
            ],
        },
        TestCase {
            msg: b"abc",
            expected: [
                "0296238ea82c6d4adb3c838ee3cb2346049c90b96d602d7bb1b469b905c9228be25c627bffee872def773d5b2a2eb57d",
                "108ed59fd9fae381abfd1d6bce2fd2fa220990f0f837fa30e0f27914ed6e1454db0d1ee957b219f61da6ff8be0d6441f",
                "153606c417e59fb331b7ae6bce4fbf7c5190c33ce9402b5ebe2b70e44fca614f3f1382a3625ed5493843d0b0a652fc3f",
                "033f90f6057aadacae7963b0a0b379dd46750c1c94a6357c99b65f63b79e321ff50fe3053330911c56b6ceea08fee656",
            ],
        },
        TestCase {
            msg: b"abcdef0123456789",
            expected: [
                "0da75be60fb6aa0e9e3143e40c42796edf15685cafe0279afd2a67c3dff1c82341f17effd402e4f1af240ea90f4b659b",
                "038af300ef34c7759a6caaa4e69363cafeed218a1f207e93b2c70d91a1263d375d6730bd6b6509dcac3ba5b567e85bf3",
                "0492f4fed741b073e5a82580f7c663f9b79e036b70ab3e51162359cec4e77c78086fe879b65ca7a47d34374c8315ac5e",
                "19b148cbdf163cf0894f29660d2e7bfb2b68e37d54cc83fd4e6e62c020eaa48709302ef8e746736c0e19342cc1ce3df4",
            ]
        },
        TestCase {
            msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                   qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                   qqqqqqqqqqqqqqqqqqqqqqqqq",
            expected: [
                "12c8c05c1d5fc7bfa847f4d7d81e294e66b9a78bc9953990c358945e1f042eedafce608b67fdd3ab0cb2e6e263b9b1ad",
                "0c5ae723be00e6c3f0efe184fdc0702b64588fe77dda152ab13099a3bacd3876767fa7bbad6d6fd90b3642e902b208f9",
                "11c624c56dbe154d759d021eec60fab3d8b852395a89de497e48504366feedd4662d023af447d66926a28076813dd646",
                "04e77ddb3ede41b5ec4396b7421dd916efc68a358a0d7425bddd253547f2fb4830522358491827265dfc5bcc1928a569",
            ]
        },
        TestCase {
            msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expected: [
                "1565c2f625032d232f13121d3cfb476f45275c303a037faa255f9da62000c2c864ea881e2bcddd111edc4a3c0da3e88d",
                "0ea4e7c33d43e17cc516a72f76437c4bf81d8f4eac69ac355d3bf9b71b8138d55dc10fd458be115afa798b55dac34be1",
                "0f8991d2a1ad662e7b6f58ab787947f1fa607fce12dde171bc17903b012091b657e15333e11701edcf5b63ba2a561247",
                "043b6f5fe4e52c839148dc66f2b3751e69a0f6ebb3d056d6465d50d4108543ecd956e10fa1640dfd9bc0030cc2558d28",
            ]
        }
    ];

    for case in cases {
        let g = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
            &case.msg, DOMAIN,
        );
        let g_uncompressed = G2Affine::from(g).to_uncompressed();

        assert_eq!(case.expected(), hex::encode(&g_uncompressed[..]));
    }
}

#[test]
fn test_hash_to_curve_07() {
    use crate::{
        g2::G2Affine,
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
    };
    use std::string::{String, ToString};

    struct TestCase {
        msg: &'static [u8],
        expected: [&'static str; 4],
    }
    impl TestCase {
        fn expected(&self) -> String {
            self.expected[0].to_string() + self.expected[1] + self.expected[2] + self.expected[3]
        }
    }

    const DOMAIN: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_TESTGEN";

    let cases = vec![
        TestCase {
            msg: b"",
            expected: [
                "0fbdae26f9f9586a46d4b0b70390d09064ef2afe5c99348438a3c7d9756471e015cb534204c1b6824617a85024c772dc",
                "0a650bd36ae7455cb3fe5d8bb1310594551456f5c6593aec9ee0c03d2f6cb693bd2c5e99d4e23cbaec767609314f51d3",
                "02e5cf8f9b7348428cc9e66b9a9b36fe45ba0b0a146290c3a68d92895b1af0e1f2d9f889fb412670ae8478d8abd4c5aa",
                "0d8d49e7737d8f9fc5cef7c4b8817633103faf2613016cb86a1f3fc29968fe2413e232d9208d2d74a89bf7a48ac36f83",
            ],
        },
        TestCase {
            msg: b"abc",
            expected: [
                "03578447618463deb106b60e609c6f7cc446dc6035f84a72801ba17c94cd800583b493b948eff0033f09086fdd7f6175",
                "1953ce6d4267939c7360756d9cca8eb34aac4633ef35369a7dc249445069888e7d1b3f9d2e75fbd468fbcbba7110ea02",
                "0184d26779ae9d4670aca9b267dbd4d3b30443ad05b8546d36a195686e1ccc3a59194aea05ed5bce7c3144a29ec047c4",
                "0882ab045b8fe4d7d557ebb59a63a35ac9f3d312581b509af0f8eaa2960cbc5e1e36bb969b6e22980b5cbdd0787fcf4e",
            ],
        },
        TestCase {
            msg: b"abcdef0123456789",
            expected: [
                "195fad48982e186ce3c5c82133aefc9b26d55979b6f530992a8849d4263ec5d57f7a181553c8799bcc83da44847bdc8d",
                "17b461fc3b96a30c2408958cbfa5f5927b6063a8ad199d5ebf2d7cdeffa9c20c85487204804fab53f950b2f87db365aa",
                "005cdf3d984e3391e7e969276fb4bc02323c5924a4449af167030d855acc2600cf3d4fab025432c6d868c79571a95bef",
                "174a3473a3af2d0302b9065e895ca4adba4ece6ce0b41148ba597001abb152f852dd9a96fb45c9de0a43d944746f833e",
            ]
        },
        TestCase {
            msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expected: [
                "123b6bd9feeba26dd4ad00f8bfda2718c9700dc093ea5287d7711844644eb981848316d3f3f57d5d3a652c6cdc816aca",
                "0a162306f3b0f2bb326f0c4fb0e1fea020019c3af796dcd1d7264f50ddae94cacf3cade74603834d44b9ab3d5d0a6c98",
                "05483f3b96d9252dd4fc0868344dfaf3c9d145e3387db23fa8e449304fab6a7b6ec9c15f05c0a1ea66ff0efcc03e001a",
                "15c1d4f1a685bb63ee67ca1fd96155e3d091e852a684b78d085fd34f6091e5249ddddbdcf2e7ec82ce6c04c63647eeb7",
            ]
        }
    ];

    for case in cases {
        let g = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
            &case.msg, DOMAIN,
        );
        let g_uncompressed = G2Affine::from(g).to_uncompressed();

        assert_eq!(case.expected(), hex::encode(&g_uncompressed[..]));
    }
}

#[test]
fn test_hash_to_curve_10() {
    use crate::{
        g2::G2Affine,
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
    };
    use std::string::{String, ToString};

    struct TestCase {
        msg: &'static [u8],
        expected: [&'static str; 4],
    }
    impl TestCase {
        fn expected(&self) -> String {
            self.expected[0].to_string() + self.expected[1] + self.expected[2] + self.expected[3]
        }
    }

    const DOMAIN: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

    let cases = vec![
        TestCase {
            msg: b"",
            expected: [
                "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d",
                "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
                "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
                "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
            ],
        },
        TestCase {
            msg: b"abc",
            expected: [
                "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
                "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
                "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16",
                "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
            ],
        },
        TestCase {
            msg: b"abcdef0123456789",
            expected: [
                "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c",
                "121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0",
                "0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be",
                "05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8",
            ]
        },
        TestCase {
            msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                   qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                   qqqqqqqqqqqqqqqqqqqqqqqqq",
            expected: [
                "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb91",
                "19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da",
                "09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e5662",
                "14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192",
            ]
        },
        TestCase {
            msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            expected: [
                "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569",
                "01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534",
                "03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52",
                "0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e",
            ]
        }
    ];

    for case in cases {
        let g = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
            &case.msg, DOMAIN,
        );
        let g_uncompressed = G2Affine::from(g).to_uncompressed();

        assert_eq!(case.expected(), hex::encode(&g_uncompressed[..]));
    }
}
