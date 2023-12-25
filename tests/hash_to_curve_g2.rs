#[cfg(test)]
#[cfg(feature = "experimental")]
mod tests {
    use bls12_381::{
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
        G2Affine, G2Projective,
    };
    use hex_literal::hex;
    use sha2::Sha256;

    struct TestCase {
        msg: &'static [u8],
        dst: &'static [u8],
        expected: &'static [u8],
    }

    impl TestCase {
        pub fn check_output(&self, output: &[u8]) {
            if output != self.expected {
                panic!(
                    "Test vector result mismatch.\n\
                    Message: {:x?}\n\
                    DST: {:x?}\n\
                    Expected: {:x?}\n\
                    Found: {:x?}",
                    self.msg, self.dst, self.expected, output
                )
            }
        }
    }

    // From <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-J.10.1>
    #[test]
    fn hash_to_curve_works_for_draft16_testvectors_g2_sha256_ro() {
        let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

        let cases = vec![
            TestCase {
                msg: b"",
                dst,
                expected: &hex!(
                    "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab
                    379ba13dff5bf5dd71b72418717047f5b0f37da03d
                    0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d693352
                    66f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a
                    12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259d
                    dc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6
                    0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11
                    062ee75ec076daf2d4bc358c4b190c0c98064fdd92"
                ),
            },
            TestCase {
                msg: b"abc",
                dst,
                expected: &hex!(
                    "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9
                    eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8
                    02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a21
                    0245129dbec7780ccc7954725f4168aff2787776e6
                    00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e
                    9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16
                    1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea0
                    5c4cfe244aeb197642555a0645fb87bf7466b2ba48"
                ),
            },
            TestCase {
                msg: b"abcdef0123456789",
                dst,
                expected: &hex!(
                    "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cb
                    ba169fb3968288b3fafb265f9ebd380512a71c3f2c
                    121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4
                    c0028add35aea8bb83d53c08cfc007c1e005723cd0
                    0bb5e7572275c567462d91807de765611490205a941a5a6af3b169
                    1bfe596c31225d3aabdf15faff860cb4ef17c7c3be
                    05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf13
                    56a6acf17574518acb506e435b639353c2e14827c8"
                ),
            },
            TestCase {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                    qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                    qqqqqqqqqqqqqqqqqqqqqqqqq",
                dst,
                expected: &hex!(
                    "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813be
                    c433f587e2d7a4fef038260eef0cef4d02aae3eb91
                    19a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24d
                    c65d4e25e50d83f0f77105e955d78f4762d33c17da
                    09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6
                    b795844f4a0673e20282d07bc69641cee04f5e5662
                    14f81cd421617428bc3b9fe25afbb751d934a00493524bc4e06563
                    5b0555084dd54679df1536101b2c979c0152d09192"
                ),
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
                dst,
                expected: &hex!(
                    "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce
                    4a34131d71f7a73e95fee3f812aea3de78b4d01569
                    01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64f
                    d24557c2f4b18ecfc5663e54ae16a84f5ab7f62534
                    03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a66
                    0a9b3994249ae4e63fac38b23da0c398689ee2ab52
                    0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9
                    db90d2b9da6cbabf48adc1adf59a1a28344e79d57e"
                ),
            },
        ];

        for case in cases {
            let g = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
                [case.msg],
                case.dst,
            );
            let aff = G2Affine::from(g);
            let g_uncompressed = aff.to_uncompressed();
            case.check_output(&g_uncompressed);
        }
    }

    // From <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-J.10.2>
    #[test]
    fn encode_to_curve_works_for_draft16_testvectors_g2_sha256_nu() {
        let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_NU_";

        let cases = vec![
            TestCase {
                msg: b"",
                dst,
                expected: &hex!(
                    "126b855e9e69b1f691f816e48ac6977664d24d99f8724868a18418
                    6469ddfd4617367e94527d4b74fc86413483afb35b
                    00e7f4568a82b4b7dc1f14c6aaa055edf51502319c723c4dc2688c
                    7fe5944c213f510328082396515734b6612c4e7bb7
                    1498aadcf7ae2b345243e281ae076df6de84455d766ab6fcdaad71
                    fab60abb2e8b980a440043cd305db09d283c895e3d
                    0caead0fd7b6176c01436833c79d305c78be307da5f6af6c133c47
                    311def6ff1e0babf57a0fb5539fce7ee12407b0a42"
                ),
            },
            TestCase {
                msg: b"abc",
                dst,
                expected: &hex!(
                    "0296238ea82c6d4adb3c838ee3cb2346049c90b96d602d7bb1b469
                    b905c9228be25c627bffee872def773d5b2a2eb57d
                    108ed59fd9fae381abfd1d6bce2fd2fa220990f0f837fa30e0f279
                    14ed6e1454db0d1ee957b219f61da6ff8be0d6441f
                    153606c417e59fb331b7ae6bce4fbf7c5190c33ce9402b5ebe2b70
                    e44fca614f3f1382a3625ed5493843d0b0a652fc3f
                    033f90f6057aadacae7963b0a0b379dd46750c1c94a6357c99b65f
                    63b79e321ff50fe3053330911c56b6ceea08fee656"
                ),
            },
            TestCase {
                msg: b"abcdef0123456789",
                dst,
                expected: &hex!(
                    "0da75be60fb6aa0e9e3143e40c42796edf15685cafe0279afd2a67
                    c3dff1c82341f17effd402e4f1af240ea90f4b659b
                    038af300ef34c7759a6caaa4e69363cafeed218a1f207e93b2c70d
                    91a1263d375d6730bd6b6509dcac3ba5b567e85bf3
                    0492f4fed741b073e5a82580f7c663f9b79e036b70ab3e51162359
                    cec4e77c78086fe879b65ca7a47d34374c8315ac5e
                    19b148cbdf163cf0894f29660d2e7bfb2b68e37d54cc83fd4e6e62
                    c020eaa48709302ef8e746736c0e19342cc1ce3df4"
                ),
            },
            TestCase {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                    qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                    qqqqqqqqqqqqqqqqqqqqqqqqq",
                dst,
                expected: &hex!(
                    "12c8c05c1d5fc7bfa847f4d7d81e294e66b9a78bc9953990c35894
                    5e1f042eedafce608b67fdd3ab0cb2e6e263b9b1ad
                    0c5ae723be00e6c3f0efe184fdc0702b64588fe77dda152ab13099
                    a3bacd3876767fa7bbad6d6fd90b3642e902b208f9
                    11c624c56dbe154d759d021eec60fab3d8b852395a89de497e4850
                    4366feedd4662d023af447d66926a28076813dd646
                    04e77ddb3ede41b5ec4396b7421dd916efc68a358a0d7425bddd25
                    3547f2fb4830522358491827265dfc5bcc1928a569"
                ),
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
                dst,
                expected: &hex!(
                    "1565c2f625032d232f13121d3cfb476f45275c303a037faa255f9d
                    a62000c2c864ea881e2bcddd111edc4a3c0da3e88d
                    0ea4e7c33d43e17cc516a72f76437c4bf81d8f4eac69ac355d3bf9
                    b71b8138d55dc10fd458be115afa798b55dac34be1
                    0f8991d2a1ad662e7b6f58ab787947f1fa607fce12dde171bc1790
                    3b012091b657e15333e11701edcf5b63ba2a561247
                    043b6f5fe4e52c839148dc66f2b3751e69a0f6ebb3d056d6465d50
                    d4108543ecd956e10fa1640dfd9bc0030cc2558d28"
                ),
            },
        ];

        for case in cases {
            let g = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::encode_to_curve(
                [case.msg],
                case.dst,
            );
            let aff = G2Affine::from(g);
            let g_uncompressed = aff.to_uncompressed();
            case.check_output(&g_uncompressed);
        }
    }
}
