//! Implementation of hash-to-curve for the G1 group

use subtle::{ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

use super::chain::chain_pm3div4;
use super::{HashToField, MapToCurve};
use crate::fp::Fp;
use crate::g1::G1Projective;
use crate::generic_array::{typenum::U64, GenericArray};

/// Coefficients of the 11-isogeny x map's numerator
const ISO11_XNUM: [Fp; 12] = [
    Fp::from_raw_unchecked([
        0x4d18b6f3af00131c,
        0x19fa219793fee28c,
        0x3f2885f1467f19ae,
        0x23dcea34f2ffb304,
        0xd15b58d2ffc00054,
        0x0913be200a20bef4,
    ]),
    Fp::from_raw_unchecked([
        0x898985385cdbbd8b,
        0x3c79e43cc7d966aa,
        0x1597e193f4cd233a,
        0x8637ef1e4d6623ad,
        0x11b22deed20d827b,
        0x07097bc5998784ad,
    ]),
    Fp::from_raw_unchecked([
        0xa542583a480b664b,
        0xfc7169c026e568c6,
        0x5ba2ef314ed8b5a6,
        0x5b5491c05102f0e7,
        0xdf6e99707d2a0079,
        0x0784151ed7605524,
    ]),
    Fp::from_raw_unchecked([
        0x494e212870f72741,
        0xab9be52fbda43021,
        0x26f5577994e34c3d,
        0x049dfee82aefbd60,
        0x65dadd7828505289,
        0x0e93d431ea011aeb,
    ]),
    Fp::from_raw_unchecked([
        0x90ee774bd6a74d45,
        0x7ada1c8a41bfb185,
        0x0f1a8953b325f464,
        0x104c24211be4805c,
        0x169139d319ea7a8f,
        0x09f20ead8e532bf6,
    ]),
    Fp::from_raw_unchecked([
        0x6ddd93e2f43626b7,
        0xa5482c9aa1ccd7bd,
        0x143245631883f4bd,
        0x2e0a94ccf77ec0db,
        0xb0282d480e56489f,
        0x18f4bfcbb4368929,
    ]),
    Fp::from_raw_unchecked([
        0x23c5f0c953402dfd,
        0x7a43ff6958ce4fe9,
        0x2c390d3d2da5df63,
        0xd0df5c98e1f9d70f,
        0xffd89869a572b297,
        0x1277ffc72f25e8fe,
    ]),
    Fp::from_raw_unchecked([
        0x79f4f0490f06a8a6,
        0x85f894a88030fd81,
        0x12da3054b18b6410,
        0xe2a57f6505880d65,
        0xbba074f260e400f1,
        0x08b76279f621d028,
    ]),
    Fp::from_raw_unchecked([
        0xe67245ba78d5b00b,
        0x8456ba9a1f186475,
        0x7888bff6e6b33bb4,
        0xe21585b9a30f86cb,
        0x05a69cdcef55feee,
        0x09e699dd9adfa5ac,
    ]),
    Fp::from_raw_unchecked([
        0x0de5c357bff57107,
        0x0a0db4ae6b1a10b2,
        0xe256bb67b3b3cd8d,
        0x8ad456574e9db24f,
        0x0443915f50fd4179,
        0x098c4bf7de8b6375,
    ]),
    Fp::from_raw_unchecked([
        0xe6b0617e7dd929c7,
        0xfe6e37d442537375,
        0x1dafdeda137a489e,
        0xe4efd1ad3f767ceb,
        0x4a51d8667f0fe1cf,
        0x054fdf4bbf1d821c,
    ]),
    Fp::from_raw_unchecked([
        0x72db2a50658d767b,
        0x8abf91faa257b3d5,
        0xe969d6833764ab47,
        0x464170142a1009eb,
        0xb14f01aadb30be2f,
        0x18ae6a856f40715d,
    ]),
];

/// Coefficients of the 11-isogeny x map's denominator
const ISO11_XDEN: [Fp; 11] = [
    Fp::from_raw_unchecked([
        0xb962a077fdb0f945,
        0xa6a9740fefda13a0,
        0xc14d568c3ed6c544,
        0xb43fc37b908b133e,
        0x9c0b3ac929599016,
        0x0165aa6c93ad115f,
    ]),
    Fp::from_raw_unchecked([
        0x23279a3ba506c1d9,
        0x92cfca0a9465176a,
        0x3b294ab13755f0ff,
        0x116dda1c5070ae93,
        0xed4530924cec2045,
        0x083383d6ed81f1ce,
    ]),
    Fp::from_raw_unchecked([
        0x9885c2a6449fecfc,
        0x4a2b54ccd37733f0,
        0x17da9ffd8738c142,
        0xa0fba72732b3fafd,
        0xff364f36e54b6812,
        0x0f29c13c660523e2,
    ]),
    Fp::from_raw_unchecked([
        0xe349cc118278f041,
        0xd487228f2f3204fb,
        0xc9d325849ade5150,
        0x43a92bd69c15c2df,
        0x1c2c7844bc417be4,
        0x12025184f407440c,
    ]),
    Fp::from_raw_unchecked([
        0x587f65ae6acb057b,
        0x1444ef325140201f,
        0xfbf995e71270da49,
        0xccda066072436a42,
        0x7408904f0f186bb2,
        0x13b93c63edf6c015,
    ]),
    Fp::from_raw_unchecked([
        0xfb918622cd141920,
        0x4a4c64423ecaddb4,
        0x0beb232927f7fb26,
        0x30f94df6f83a3dc2,
        0xaeedd424d780f388,
        0x06cc402dd594bbeb,
    ]),
    Fp::from_raw_unchecked([
        0xd41f761151b23f8f,
        0x32a92465435719b3,
        0x64f436e888c62cb9,
        0xdf70a9a1f757c6e4,
        0x6933a38d5b594c81,
        0x0c6f7f7237b46606,
    ]),
    Fp::from_raw_unchecked([
        0x693c08747876c8f7,
        0x22c9850bf9cf80f0,
        0x8e9071dab950c124,
        0x89bc62d61c7baf23,
        0xbc6be2d8dad57c23,
        0x17916987aa14a122,
    ]),
    Fp::from_raw_unchecked([
        0x1be3ff439c1316fd,
        0x9965243a7571dfa7,
        0xc7f7f62962f5cd81,
        0x32c6aa9af394361c,
        0xbbc2ee18e1c227f4,
        0x0c102cbac531bb34,
    ]),
    Fp::from_raw_unchecked([
        0x997614c97bacbf07,
        0x61f86372b99192c0,
        0x5b8c95fc14353fc3,
        0xca2b066c2a87492f,
        0x16178f5bbf698711,
        0x12a6dcd7f0f4e0e8,
    ]),
    Fp::from_raw_unchecked([
        0x760900000002fffd,
        0xebf4000bc40c0002,
        0x5f48985753c758ba,
        0x77ce585370525745,
        0x5c071a97a256ec6d,
        0x15f65ec3fa80e493,
    ]),
];

/// Coefficients of the 11-isogeny y map's numerator
const ISO11_YNUM: [Fp; 16] = [
    Fp::from_raw_unchecked([
        0x2b567ff3e2837267,
        0x1d4d9e57b958a767,
        0xce028fea04bd7373,
        0xcc31a30a0b6cd3df,
        0x7d7b18a682692693,
        0x0d300744d42a0310,
    ]),
    Fp::from_raw_unchecked([
        0x99c2555fa542493f,
        0xfe7f53cc4874f878,
        0x5df0608b8f97608a,
        0x14e03832052b49c8,
        0x706326a6957dd5a4,
        0x0a8dadd9c2414555,
    ]),
    Fp::from_raw_unchecked([
        0x13d942922a5cf63a,
        0x357e33e36e261e7d,
        0xcf05a27c8456088d,
        0x0000bd1de7ba50f0,
        0x83d0c7532f8c1fde,
        0x13f70bf38bbf2905,
    ]),
    Fp::from_raw_unchecked([
        0x5c57fd95bfafbdbb,
        0x28a359a65e541707,
        0x3983ceb4f6360b6d,
        0xafe19ff6f97e6d53,
        0xb3468f4550192bf7,
        0x0bb6cde49d8ba257,
    ]),
    Fp::from_raw_unchecked([
        0x590b62c7ff8a513f,
        0x314b4ce372cacefd,
        0x6bef32ce94b8a800,
        0x6ddf84a095713d5f,
        0x64eace4cb0982191,
        0x0386213c651b888d,
    ]),
    Fp::from_raw_unchecked([
        0xa5310a31111bbcdd,
        0xa14ac0f5da148982,
        0xf9ad9cc95423d2e9,
        0xaa6ec095283ee4a7,
        0xcf5b1f022e1c9107,
        0x01fddf5aed881793,
    ]),
    Fp::from_raw_unchecked([
        0x65a572b0d7a7d950,
        0xe25c2d8183473a19,
        0xc2fcebe7cb877dbd,
        0x05b2d36c769a89b0,
        0xba12961be86e9efb,
        0x07eb1b29c1dfde1f,
    ]),
    Fp::from_raw_unchecked([
        0x93e09572f7c4cd24,
        0x364e929076795091,
        0x8569467e68af51b5,
        0xa47da89439f5340f,
        0xf4fa918082e44d64,
        0x0ad52ba3e6695a79,
    ]),
    Fp::from_raw_unchecked([
        0x911429844e0d5f54,
        0xd03f51a3516bb233,
        0x3d587e5640536e66,
        0xfa86d2a3a9a73482,
        0xa90ed5adf1ed5537,
        0x149c9c326a5e7393,
    ]),
    Fp::from_raw_unchecked([
        0x462bbeb03c12921a,
        0xdc9af5fa0a274a17,
        0x9a558ebde836ebed,
        0x649ef8f11a4fae46,
        0x8100e1652b3cdc62,
        0x1862bd62c291dacb,
    ]),
    Fp::from_raw_unchecked([
        0x05c9b8ca89f12c26,
        0x0194160fa9b9ac4f,
        0x6a643d5a6879fa2c,
        0x14665bdd8846e19d,
        0xbb1d0d53af3ff6bf,
        0x12c7e1c3b28962e5,
    ]),
    Fp::from_raw_unchecked([
        0xb55ebf900b8a3e17,
        0xfedc77ec1a9201c4,
        0x1f07db10ea1a4df4,
        0x0dfbd15dc41a594d,
        0x389547f2334a5391,
        0x02419f98165871a4,
    ]),
    Fp::from_raw_unchecked([
        0xb416af000745fc20,
        0x8e563e9d1ea6d0f5,
        0x7c763e17763a0652,
        0x01458ef0159ebbef,
        0x8346fe421f96bb13,
        0x0d2d7b829ce324d2,
    ]),
    Fp::from_raw_unchecked([
        0x93096bb538d64615,
        0x6f2a2619951d823a,
        0x8f66b3ea59514fa4,
        0xf563e63704f7092f,
        0x724b136c4cf2d9fa,
        0x046959cfcfd0bf49,
    ]),
    Fp::from_raw_unchecked([
        0xea748d4b6e405346,
        0x91e9079c2c02d58f,
        0x41064965946d9b59,
        0xa06731f1d2bbe1ee,
        0x07f897e267a33f1b,
        0x1017290919210e5f,
    ]),
    Fp::from_raw_unchecked([
        0x872aa6c17d985097,
        0xeecc53161264562a,
        0x07afe37afff55002,
        0x54759078e5be6838,
        0xc4b92d15db8acca8,
        0x106d87d1b51d13b9,
    ]),
];

/// Coefficients of the 11-isogeny y map's denominator
const ISO11_YDEN: [Fp; 16] = [
    Fp::from_raw_unchecked([
        0xeb6c359d47e52b1c,
        0x18ef5f8a10634d60,
        0xddfa71a0889d5b7e,
        0x723e71dcc5fc1323,
        0x52f45700b70d5c69,
        0x0a8b981ee47691f1,
    ]),
    Fp::from_raw_unchecked([
        0x616a3c4f5535b9fb,
        0x6f5f037395dbd911,
        0xf25f4cc5e35c65da,
        0x3e50dffea3c62658,
        0x6a33dca523560776,
        0x0fadeff77b6bfe3e,
    ]),
    Fp::from_raw_unchecked([
        0x2be9b66df470059c,
        0x24a2c159a3d36742,
        0x115dbe7ad10c2a37,
        0xb6634a652ee5884d,
        0x04fe8bb2b8d81af4,
        0x01c2a7a256fe9c41,
    ]),
    Fp::from_raw_unchecked([
        0xf27bf8ef3b75a386,
        0x898b367476c9073f,
        0x24482e6b8c2f4e5f,
        0xc8e0bbd6fe110806,
        0x59b0c17f7631448a,
        0x11037cd58b3dbfbd,
    ]),
    Fp::from_raw_unchecked([
        0x31c7912ea267eec6,
        0x1dbf6f1c5fcdb700,
        0xd30d4fe3ba86fdb1,
        0x3cae528fbee9a2a4,
        0xb1cce69b6aa9ad9a,
        0x044393bb632d94fb,
    ]),
    Fp::from_raw_unchecked([
        0xc66ef6efeeb5c7e8,
        0x9824c289dd72bb55,
        0x71b1a4d2f119981d,
        0x104fc1aafb0919cc,
        0x0e49df01d942a628,
        0x096c3a09773272d4,
    ]),
    Fp::from_raw_unchecked([
        0x9abc11eb5fadeff4,
        0x32dca50a885728f0,
        0xfb1fa3721569734c,
        0xc4b76271ea6506b3,
        0xd466a75599ce728e,
        0x0c81d4645f4cb6ed,
    ]),
    Fp::from_raw_unchecked([
        0x4199f10e5b8be45b,
        0xda64e495b1e87930,
        0xcb353efe9b33e4ff,
        0x9e9efb24aa6424c6,
        0xf08d33680a237465,
        0x0d3378023e4c7406,
    ]),
    Fp::from_raw_unchecked([
        0x7eb4ae92ec74d3a5,
        0xc341b4aa9fac3497,
        0x5be603899e907687,
        0x03bfd9cca75cbdeb,
        0x564c2935a96bfa93,
        0x0ef3c33371e2fdb5,
    ]),
    Fp::from_raw_unchecked([
        0x7ee91fd449f6ac2e,
        0xe5d5bd5cb9357a30,
        0x773a8ca5196b1380,
        0xd0fda172174ed023,
        0x6cb95e0fa776aead,
        0x0d22d5a40cec7cff,
    ]),
    Fp::from_raw_unchecked([
        0xf727e09285fd8519,
        0xdc9d55a83017897b,
        0x7549d8bd057894ae,
        0x178419613d90d8f8,
        0xfce95ebdeb5b490a,
        0x0467ffaef23fc49e,
    ]),
    Fp::from_raw_unchecked([
        0xc1769e6a7c385f1b,
        0x79bc930deac01c03,
        0x5461c75a23ede3b5,
        0x6e20829e5c230c45,
        0x828e0f1e772a53cd,
        0x116aefa749127bff,
    ]),
    Fp::from_raw_unchecked([
        0x101c10bf2744c10a,
        0xbbf18d053a6a3154,
        0xa0ecf39ef026f602,
        0xfc009d4996dc5153,
        0xb9000209d5bd08d3,
        0x189e5fe4470cd73c,
    ]),
    Fp::from_raw_unchecked([
        0x7ebd546ca1575ed2,
        0xe47d5a981d081b55,
        0x57b2b625b6d4ca21,
        0xb0a1ba04228520cc,
        0x98738983c2107ff3,
        0x13dddbc4799d81d6,
    ]),
    Fp::from_raw_unchecked([
        0x09319f2e39834935,
        0x039e952cbdb05c21,
        0x55ba77a9a2f76493,
        0xfd04e3dfc6086467,
        0xfb95832e7d78742e,
        0x0ef9c24eccaf5e0e,
    ]),
    Fp::from_raw_unchecked([
        0x760900000002fffd,
        0xebf4000bc40c0002,
        0x5f48985753c758ba,
        0x77ce585370525745,
        0x5c071a97a256ec6d,
        0x15f65ec3fa80e493,
    ]),
];

const SSWU_ELLP_A: Fp = Fp::from_raw_unchecked([
    0x2f65aa0e9af5aa51,
    0x86464c2d1e8416c3,
    0xb85ce591b7bd31e2,
    0x27e11c91b5f24e7c,
    0x28376eda6bfc1835,
    0x155455c3e5071d85,
]);

const SSWU_ELLP_B: Fp = Fp::from_raw_unchecked([
    0xfb996971fe22a1e0,
    0x9aa93eb35b742d6f,
    0x8c476013de99c5c4,
    0x873e27c3a221e571,
    0xca72b5e45a52d888,
    0x06824061418a386b,
]);

const SSWU_XI: Fp = Fp::from_raw_unchecked([
    0x886c00000023ffdc,
    0x0f70008d3090001d,
    0x77672417ed5828c3,
    0x9dac23e943dc1740,
    0x50553f1b9c131521,
    0x078c712fbe0ab6e8,
]);

const SQRT_M_XI_CUBED: Fp = Fp::from_raw_unchecked([
    0x43b571cad3215f1f,
    0xccb460ef1c702dc2,
    0x742d884f4f97100b,
    0xdb2c3e3238a3382b,
    0xe40f3fa13fce8f88,
    0x0073a2af9892a2ff,
]);

impl HashToField for G1Projective {
    type InputLength = U64;
    type Pt = Fp;

    fn input_okm(okm: &GenericArray<u8, U64>) -> Fp {
        const F_2_256: Fp = Fp::from_raw_unchecked([
            0x75b3cd7c5ce820f,
            0x3ec6ba621c3edb0b,
            0x168a13d82bff6bce,
            0x87663c4bf8c449d2,
            0x15f34c83ddc8d830,
            0xf9628b49caa2e85,
        ]);

        let mut bs = [0u8; 48];
        bs[16..].copy_from_slice(&okm[..32]);
        let db = Fp::from_bytes(&bs).unwrap();

        bs[16..].copy_from_slice(&okm[32..]);
        let da = Fp::from_bytes(&bs).unwrap();

        db * F_2_256 + da
    }
}

/// Map from a field element to a point on the curve E-prime
fn map_to_curve_simple_ssw(u: &Fp) -> G1Projective {
    let usq = u.square();
    let xi_usq = SSWU_XI * usq;
    let xisq_u4 = xi_usq.square();
    let nd_common = xisq_u4 + xi_usq; // XI^2 * u^4 + XI * u^2
    let x_den = SSWU_ELLP_A * Fp::conditional_select(&(-nd_common), &SSWU_XI, nd_common.is_zero());
    let x0_num = SSWU_ELLP_B * (Fp::one() + nd_common); // B * (1 + (XI^2 * u^4 + XI * u^2))

    // compute g(x0(u))
    let x_densq = x_den.square();
    let gx_den = x_densq * x_den;
    // x0_num^3 + A * x0_num * x_den^2 + B * x_den^3
    let gx0_num = (x0_num.square() + SSWU_ELLP_A * x_densq) * x0_num + SSWU_ELLP_B * gx_den;

    // compute g(X0(u)) ^ ((p - 3) // 4)
    let sqrt_candidate = {
        let u_v = gx0_num * gx_den; // u*v
        let vsq = gx_den.square(); // v^2
        u_v * chain_pm3div4(&(u_v * vsq)) // u v (u v^3) ^ ((p - 3) // 4)
    };

    let gx0_square = (sqrt_candidate.square() * gx_den).ct_eq(&gx0_num); // g(x0) is square
    let x1_num = x0_num * xi_usq;
    // sqrt(-XI**3) * u^3 g(x0) ^ ((p - 1) // 4)
    let y1 = SQRT_M_XI_CUBED * usq * u * sqrt_candidate;

    let x_num = Fp::conditional_select(&x1_num, &x0_num, gx0_square);
    let mut y = Fp::conditional_select(&y1, &sqrt_candidate, gx0_square);
    // ensure sign of y and sign of u agree
    y.conditional_negate(y.sgn0() ^ u.sgn0());

    G1Projective {
        x: x_num,
        y: y * x_den,
        z: x_den,
    }
}

/// Map from a point on the curve E-prime to curve E
fn iso_map(u: &G1Projective) -> G1Projective {
    const COEFFS: [&[Fp]; 4] = [&ISO11_XNUM, &ISO11_XDEN, &ISO11_YNUM, &ISO11_YDEN];

    // unpack input point
    let G1Projective { x, y, z } = *u;

    let mut mapvals = [Fp::zero(); 4];

    let zpows = {
        let mut zpows = [Fp::zero(); 15];
        zpows[0] = z;
        for idx in 1..zpows.len() {
            zpows[idx] = zpows[idx - 1] * z;
        }
        zpows
    };

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
    G1Projective {
        x: mapvals[0] * mapvals[3], // xnum * yden,
        y: mapvals[2] * mapvals[1], // ynum * xden,
        z: mapvals[1] * mapvals[3], // xden * yden
    }
}

impl MapToCurve for G1Projective {
    fn map_to_curve_simple_ssw(u: &Fp) -> G1Projective {
        let pt = map_to_curve_simple_ssw(u);
        iso_map(&pt)
    }

    fn clear_h(&self) -> Self {
        self.clear_cofactor()
    }
}

#[cfg(test)]
fn check_g1_prime(pt: &G1Projective) -> bool {
    // (X : Y : Z)==(X/Z, Y/Z) is on E': y^2 = x^3 + A * x + B.
    // y^2 z = (x^3) + A (x z^2) + B z^3
    let zsq = pt.z.square();
    (pt.y.square() * pt.z)
        == (pt.x.square() * pt.x + SSWU_ELLP_A * pt.x * zsq + SSWU_ELLP_B * zsq * pt.z)
}

#[test]
fn test_simple_swu_expected() {
    // exceptional case: zero
    let p = map_to_curve_simple_ssw(&Fp::zero());
    let G1Projective { x, y, z } = &p;
    let xo = Fp::from_raw_unchecked([
        0xfb996971fe22a1e0,
        0x9aa93eb35b742d6f,
        0x8c476013de99c5c4,
        0x873e27c3a221e571,
        0xca72b5e45a52d888,
        0x6824061418a386b,
    ]);
    let yo = Fp::from_raw_unchecked([
        0xfd6fced87a7f11a3,
        0x9a6b314b03c8db31,
        0x41f85416e0eab593,
        0xfeeb089f7e6ec4d7,
        0x85a134c37ed1278f,
        0x575c525bb9f74bb,
    ]);
    let zo = Fp::from_raw_unchecked([
        0x7f674ea0a8915178,
        0xb0f945fc13b8fa65,
        0x4b46759a38e87d76,
        0x2e7a929641bbb6a1,
        0x1668ddfa462bf6b6,
        0x960e2ed1cf294c,
    ]);
    assert_eq!(x, &xo);
    assert_eq!(y, &yo);
    assert_eq!(z, &zo);
    assert!(check_g1_prime(&p));

    // exceptional case: sqrt(-1/XI) (positive)
    let excp = Fp::from_raw_unchecked([
        0xf3d0477e91edbf,
        0x8d6621e4ca8dc69,
        0xb9cf7927b19b9726,
        0xba133c996cafa2ec,
        0xed2a5ccd5ca7bb68,
        0x19cb022f8ee9d73b,
    ]);
    let p = map_to_curve_simple_ssw(&excp);
    let G1Projective { x, y, z } = &p;
    assert_eq!(x, &xo);
    assert_eq!(y, &yo);
    assert_eq!(z, &zo);
    assert!(check_g1_prime(&p));

    // exceptional case: sqrt(-1/XI) (negative)
    let excp = Fp::from_raw_unchecked([
        0xb90b2fb8816dbcec,
        0x15d59de064ab2396,
        0xad61597945155efe,
        0xaa640eeb86d56fd2,
        0x5df14ae8e6a3f16e,
        0x360fbaaa960f5e,
    ]);
    let p = map_to_curve_simple_ssw(&excp);
    let G1Projective { x, y, z } = &p;
    let myo = -yo;
    assert_eq!(x, &xo);
    assert_eq!(y, &myo);
    assert_eq!(z, &zo);
    assert!(check_g1_prime(&p));

    let u = Fp::from_raw_unchecked([
        0xa618fa19f7e2eadc,
        0x93c7f1fc876ba245,
        0xe2ed4cc47b5c0ae0,
        0xd49efa74e4a8d000,
        0xa0b23ba692b5431c,
        0xd1551f2d7d8d193,
    ]);
    let xo = Fp::from_raw_unchecked([
        0x2197ca55fab3ba48,
        0x591deb39f434949a,
        0xf9df7fb4f1fa6a08,
        0x59e3c16a9dfa8fa5,
        0xe5929b194aad5f7a,
        0x130a46a4c61b44ed,
    ]);
    let yo = Fp::from_raw_unchecked([
        0xf7215b58c7200ad0,
        0x890516313a4e66bf,
        0xc9031acc8a3619a8,
        0xea1f9978fde3ffec,
        0x548f02d6cfbf472,
        0x169375573529163f,
    ]);
    let zo = Fp::from_raw_unchecked([
        0xf36feb2e1128ade0,
        0x42e22214250bcd94,
        0xb94f6ba2dddf62d6,
        0xf56d4392782bf0a2,
        0xb2d7ce1ec26309e7,
        0x182b57ed6b99f0a1,
    ]);
    let p = map_to_curve_simple_ssw(&u);
    let G1Projective { x, y, z } = &p;
    assert_eq!(x, &xo);
    assert_eq!(y, &yo);
    assert_eq!(z, &zo);
    assert!(check_g1_prime(&p));
}

#[test]
fn test_osswu_semirandom() {
    use rand_core::SeedableRng;
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    for _ in 0..32 {
        let input = Fp::random(&mut rng);
        let p = map_to_curve_simple_ssw(&input);
        assert!(check_g1_prime(&p));

        let p_iso = iso_map(&p);
        assert!(bool::from(p_iso.is_on_curve()));
    }
}

#[test]
fn test_encode_to_curve_07() {
    use crate::{
        g1::G1Affine,
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
    };
    use std::string::{String, ToString};

    struct TestCase {
        msg: &'static [u8],
        expected: [&'static str; 2],
    }
    impl TestCase {
        fn expected(&self) -> String {
            self.expected[0].to_string() + self.expected[1]
        }
    }

    const DOMAIN: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_NU_TESTGEN";

    let cases = vec![
        TestCase {
            msg: b"",
            expected: [
        "1223effdbb2d38152495a864d78eee14cb0992d89a241707abb03819a91a6d2fd65854ab9a69e9aacb0cbebfd490732c",
        "0f925d61e0b235ecd945cbf0309291878df0d06e5d80d6b84aa4ff3e00633b26f9a7cb3523ef737d90e6d71e8b98b2d5",
            ],
        },
        TestCase {
            msg: b"abc",
            expected: [
        "179d3fd0b4fb1da43aad06cea1fb3f828806ddb1b1fa9424b1e3944dfdbab6e763c42636404017da03099af0dcca0fd6",
        "0d037cb1c6d495c0f5f22b061d23f1be3d7fe64d3c6820cfcd99b6b36fa69f7b4c1f4addba2ae7aa46fb25901ab483e4",
            ],
        },
        TestCase {
            msg: b"abcdef0123456789",
            expected: [
        "15aa66c77eded1209db694e8b1ba49daf8b686733afaa7b68c683d0b01788dfb0617a2e2d04c0856db4981921d3004af",
        "0952bb2f61739dd1d201dd0a79d74cda3285403d47655ee886afe860593a8a4e51c5b77a22d2133e3a4280eaaaa8b788",
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
        "06328ce5106e837935e8da84bd9af473422e62492930aa5f460369baad9545defa468d9399854c23a75495d2a80487ee",
        "094bfdfe3e552447433b5a00967498a3f1314b86ce7a7164c8a8f4131f99333b30a574607e301d5f774172c627fd0bca",
            ]
        }
    ];

    for case in cases {
        let g = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
            &case.msg, DOMAIN,
        );
        let aff = G1Affine::from(g);
        let g_uncompressed = aff.to_uncompressed();

        assert_eq!(case.expected(), hex::encode(&g_uncompressed[..]));
    }
}

#[test]
fn test_encode_to_curve_10() {
    use crate::{
        g1::G1Affine,
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
    };
    use std::string::{String, ToString};

    struct TestCase {
        msg: &'static [u8],
        expected: [&'static str; 2],
    }
    impl TestCase {
        fn expected(&self) -> String {
            self.expected[0].to_string() + self.expected[1]
        }
    }

    const DOMAIN: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_NU_";

    let cases = vec![
        TestCase {
            msg: b"",
            expected: [
        "184bb665c37ff561a89ec2122dd343f20e0f4cbcaec84e3c3052ea81d1834e192c426074b02ed3dca4e7676ce4ce48ba",
        "04407b8d35af4dacc809927071fc0405218f1401a6d15af775810e4e460064bcc9468beeba82fdc751be70476c888bf3",
            ],
        },
        TestCase {
            msg: b"abc",
            expected: [
        "009769f3ab59bfd551d53a5f846b9984c59b97d6842b20a2c565baa167945e3d026a3755b6345df8ec7e6acb6868ae6d",
        "1532c00cf61aa3d0ce3e5aa20c3b531a2abd2c770a790a2613818303c6b830ffc0ecf6c357af3317b9575c567f11cd2c",
            ],
        },
        TestCase {
            msg: b"abcdef0123456789",
            expected: [
        "1974dbb8e6b5d20b84df7e625e2fbfecb2cdb5f77d5eae5fb2955e5ce7313cae8364bc2fff520a6c25619739c6bdcb6a",
        "15f9897e11c6441eaa676de141c8d83c37aab8667173cbe1dfd6de74d11861b961dccebcd9d289ac633455dfcc7013a3",
            ]
        },
        TestCase {
            msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                   qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                   qqqqqqqqqqqqqqqqqqqqqqqqq",
            expected: [
        "0a7a047c4a8397b3446450642c2ac64d7239b61872c9ae7a59707a8f4f950f101e766afe58223b3bff3a19a7f754027c",
        "1383aebba1e4327ccff7cf9912bda0dbc77de048b71ef8c8a81111d71dc33c5e3aa6edee9cf6f5fe525d50cc50b77cc9",
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
        "0e7a16a975904f131682edbb03d9560d3e48214c9986bd50417a77108d13dc957500edf96462a3d01e62dc6cd468ef11",
        "0ae89e677711d05c30a48d6d75e76ca9fb70fe06c6dd6ff988683d89ccde29ac7d46c53bb97a59b1901abf1db66052db",
            ]
        }
    ];

    for case in cases {
        let g = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::encode_to_curve(
            &case.msg, DOMAIN,
        );
        let aff = G1Affine::from(g);
        let g_uncompressed = aff.to_uncompressed();

        assert_eq!(case.expected(), hex::encode(&g_uncompressed[..]));
    }
}

#[test]
fn test_hash_to_curve_07() {
    use crate::{
        g1::G1Affine,
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
    };
    use std::string::{String, ToString};

    struct TestCase {
        msg: &'static [u8],
        expected: [&'static str; 2],
    }
    impl TestCase {
        fn expected(&self) -> String {
            self.expected[0].to_string() + self.expected[1]
        }
    }

    const DOMAIN: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_TESTGEN";

    let cases = vec![
        TestCase {
            msg: b"",
            expected: [
                "0576730ab036cbac1d95b38dca905586f28d0a59048db4e8778782d89bff856ddef89277ead5a21e2975c4a6e3d8c79e",
                "1273e568bebf1864393c517f999b87c1eaa1b8432f95aea8160cd981b5b05d8cd4a7cf00103b6ef87f728e4b547dd7ae",
            ],
        },
        TestCase {
            msg: b"abc",
            expected: [
                "061daf0cc00d8912dac1d4cf5a7c32fca97f8b3bf3f805121888e5eb89f77f9a9f406569027ac6d0e61b1229f42c43d6",
                "0de1601e5ba02cb637c1d35266f5700acee9850796dc88e860d022d7b9e7e3dce5950952e97861e5bb16d215c87f030d"
            ],
        },
        TestCase {
            msg: b"abcdef0123456789",
            expected: [
                "0fb3455436843e76079c7cf3dfef75e5a104dfe257a29a850c145568d500ad31ccfe79be9ae0ea31a722548070cf98cd",
                "177989f7e2c751658df1b26943ee829d3ebcf131d8f805571712f3a7527ee5334ecff8a97fc2a50cea86f5e6212e9a57"
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
                "0514af2137c1ae1d78d5cb97ee606ea142824c199f0f25ac463a0c78200de57640d34686521d3e9cf6b3721834f8a038",
                "047a85d6898416a0899e26219bca7c4f0fa682717199de196b02b95eaf9fb55456ac3b810e78571a1b7f5692b7c58ab6"
            ]
        }
    ];

    for case in cases {
        let g = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
            &case.msg, DOMAIN,
        );
        let g_uncompressed = G1Affine::from(g).to_uncompressed();

        assert_eq!(case.expected(), hex::encode(&g_uncompressed[..]));
    }
}

#[test]
fn test_hash_to_curve_10() {
    use crate::{
        g1::G1Affine,
        hash_to_curve::{ExpandMsgXmd, HashToCurve},
    };
    use std::string::{String, ToString};

    struct TestCase {
        msg: &'static [u8],
        expected: [&'static str; 2],
    }
    impl TestCase {
        fn expected(&self) -> String {
            self.expected[0].to_string() + self.expected[1]
        }
    }

    const DOMAIN: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

    let cases = vec![
        TestCase {
            msg: b"",
            expected: [
                "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
                "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
            ],
        },
        TestCase {
            msg: b"abc",
            expected: [
                "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
                "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d"
            ],
        },
        TestCase {
            msg: b"abcdef0123456789",
            expected: [
                "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
                "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709"
            ]
        },
        TestCase {
            msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                   qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
                   qqqqqqqqqqqqqqqqqqqqqqqqq",
            expected: [
                "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
                "1807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38"
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
                "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
                "05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8"
            ]
        }
    ];

    for case in cases {
        let g = <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
            &case.msg, DOMAIN,
        );
        let g_uncompressed = G1Affine::from(g).to_uncompressed();

        assert_eq!(case.expected(), hex::encode(&g_uncompressed[..]));
    }
}
