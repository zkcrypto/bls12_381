#[cfg(test)]
#[cfg(feature = "experimental")]
mod tests {
    use bls12_381::{
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
        G1Affine, G1Projective,
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

    // From <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-J.9.1>
    #[test]
    fn hash_to_curve_works_for_draft16_testvectors_g1_sha256_ro() {
        let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

        let cases = vec![
            TestCase {
                msg: b"",
                dst,
                expected: &hex!(
                    "052926add2207b76ca4fa57a8734416c8dc95e24501772c8142787
                    00eed6d1e4e8cf62d9c09db0fac349612b759e79a1
                    08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c6
                    7e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"
                ),
            },
            TestCase {
                msg: b"abc",
                dst,
                expected: &hex!(
                    "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a794
                    3388a49a3aee664ba5379a7655d3c68900be2f6903
                    0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67
                    af215533311f0b8dfaaa154fa6b88176c229f2885d"
                ),
            },
            TestCase {
                msg: b"abcdef0123456789",
                dst,
                expected: &hex!(
                    "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf26
                    8c263ddd57a6a27200a784cbc248e84f357ce82d98
                    03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa
                    1f517c0889501dc7413753f9599b099ebcbbd2d709"
                ),
            },
            TestCase {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                    qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                    qqqqqqqqqqqqqqqqqqqqqqqqq",
                dst,
                expected: &hex!(
                    "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677c
                    f22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488
                    1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443
                    076715f91bb90a48ba1e370edce6ae1062f5e6dd38"
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
                    "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aab
                    dc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe
                    05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779a
                    d1e942856a20c438e8d99bc8abfbf74729ce1f7ac8"
                ),
            },
        ];

        for case in cases {
            let g = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(
                [case.msg],
                case.dst,
            );
            let aff = G1Affine::from(g);
            let g_uncompressed = aff.to_uncompressed();
            case.check_output(&g_uncompressed);
        }
    }

    // From <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#appendix-J.9.2>
    #[test]
    fn encode_to_curve_works_for_draft16_testvectors_g1_sha256_nu() {
        let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_NU_";

        let cases = vec![
            TestCase {
                msg: b"",
                dst,
                expected: &hex!(
                    "184bb665c37ff561a89ec2122dd343f20e0f4cbcaec84e3c3052ea
                    81d1834e192c426074b02ed3dca4e7676ce4ce48ba
                    04407b8d35af4dacc809927071fc0405218f1401a6d15af775810e
                    4e460064bcc9468beeba82fdc751be70476c888bf3"
                ),
            },
            TestCase {
                msg: b"abc",
                dst,
                expected: &hex!(
                    "009769f3ab59bfd551d53a5f846b9984c59b97d6842b20a2c565ba
                    a167945e3d026a3755b6345df8ec7e6acb6868ae6d
                    1532c00cf61aa3d0ce3e5aa20c3b531a2abd2c770a790a26138183
                    03c6b830ffc0ecf6c357af3317b9575c567f11cd2c"
                ),
            },
            TestCase {
                msg: b"abcdef0123456789",
                dst,
                expected: &hex!(
                    "1974dbb8e6b5d20b84df7e625e2fbfecb2cdb5f77d5eae5fb2955e
                    5ce7313cae8364bc2fff520a6c25619739c6bdcb6a
                    15f9897e11c6441eaa676de141c8d83c37aab8667173cbe1dfd6de
                    74d11861b961dccebcd9d289ac633455dfcc7013a3"
                ),
            },
            TestCase {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                    qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                    qqqqqqqqqqqqqqqqqqqqqqqqq",
                dst,
                expected: &hex!(
                    "0a7a047c4a8397b3446450642c2ac64d7239b61872c9ae7a59707a
                    8f4f950f101e766afe58223b3bff3a19a7f754027c
                    1383aebba1e4327ccff7cf9912bda0dbc77de048b71ef8c8a81111
                    d71dc33c5e3aa6edee9cf6f5fe525d50cc50b77cc9"
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
                    "0e7a16a975904f131682edbb03d9560d3e48214c9986bd50417a77
                    108d13dc957500edf96462a3d01e62dc6cd468ef11
                    0ae89e677711d05c30a48d6d75e76ca9fb70fe06c6dd6ff988683d
                    89ccde29ac7d46c53bb97a59b1901abf1db66052db"
                ),
            },
        ];

        for case in cases {
            let g = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::encode_to_curve(
                [case.msg],
                case.dst,
            );
            let aff = G1Affine::from(g);
            let g_uncompressed = aff.to_uncompressed();
            case.check_output(&g_uncompressed);
        }
    }
}
