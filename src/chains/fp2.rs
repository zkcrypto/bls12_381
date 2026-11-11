use crate::fp2::Fp2;

#[inline(always)]
fn sqr_n(x: Fp2, n: usize) -> Fp2 {
    (0..n).fold(x, |x, _| x.square())
}

/// Addition chain for `(p² - 9) / 16`, where p is the base-field modulus.
///
/// Generated with `addchain 0.3.1` (754 squarings and 137 multiplications).
/// `pow_vartime_extended` over the same constant costs 768 squarings and 366
/// multiplications.
#[cfg(feature = "experimental")]
#[inline(always)]
pub(crate) fn pow_by_p_squared_minus9_over16(x: &Fp2) -> Fp2 {
    let t1 = x.square();
    let t2 = t1 * x;
    let t3 = t2 * t1;
    let t4 = t3 * t1;
    let t5 = t4 * t1;
    let t6 = t5 * t1;
    let t7 = t6 * t1;
    let t8 = t7 * t1;
    let t9 = t8 * t1;
    let t10 = t9 * t1;
    let t11 = t10 * t1;
    let t12 = t11 * t1;
    let t13 = t12 * t1;
    let t14 = t13 * t1;
    let t15 = t14 * t1;
    let t16 = t15 * t1;
    let t17 = t16 * t1;
    let t18 = t17 * t1;
    let t19 = t18 * t1;
    let t20 = t19 * t1;
    let t21 = t20 * t1;
    let t29 = sqr_n(t11, 8);
    let t30 = t29 * t17;
    let t35 = sqr_n(t30, 5);
    let t36 = t35 * t12;
    let t42 = sqr_n(t36, 6);
    let t43 = t42 * t21;
    let t50 = sqr_n(t43, 7);
    let t51 = t50 * t12;
    let t56 = sqr_n(t51, 5);
    let t57 = t56 * t2;
    let t63 = sqr_n(t57, 6);
    let t64 = t63 * t2;
    let t69 = sqr_n(t64, 5);
    let t70 = t69 * t6;
    let t75 = sqr_n(t70, 5);
    let t76 = t75 * t16;
    let t84 = sqr_n(t76, 8);
    let t85 = t84 * t15;
    let t92 = sqr_n(t85, 7);
    let t93 = t92 * t12;
    let t99 = sqr_n(t93, 6);
    let t100 = t99 * t21;
    let t106 = sqr_n(t100, 6);
    let t107 = t106 * t8;
    let t115 = sqr_n(t107, 8);
    let t116 = t115 * t15;
    let t122 = sqr_n(t116, 6);
    let t123 = t122 * t11;
    let t131 = sqr_n(t123, 8);
    let t132 = t131 * t9;
    let t137 = sqr_n(t132, 5);
    let t138 = t137 * t8;
    let t146 = sqr_n(t138, 8);
    let t147 = t146 * t19;
    let t152 = sqr_n(t147, 5);
    let t153 = t152 * t15;
    let t159 = sqr_n(t153, 6);
    let t160 = t159 * t8;
    let t167 = sqr_n(t160, 7);
    let t168 = t167 * t6;
    let t172 = sqr_n(t168, 4);
    let t173 = t172 * t4;
    let t179 = sqr_n(t173, 6);
    let t180 = t179 * t5;
    let t187 = sqr_n(t180, 7);
    let t188 = t187 * t4;
    let t193 = sqr_n(t188, 5);
    let t194 = t193 * t3;
    let t201 = sqr_n(t194, 7);
    let t202 = t201 * t4;
    let t207 = sqr_n(t202, 5);
    let t208 = t207 * t4;
    let t219 = sqr_n(t208, 11);
    let t220 = t219 * t18;
    let t225 = sqr_n(t220, 5);
    let t226 = t225 * t6;
    let t233 = sqr_n(t226, 7);
    let t234 = t233 * t18;
    let t241 = sqr_n(t234, 7);
    let t242 = t241 * t14;
    let t248 = sqr_n(t242, 6);
    let t249 = t248 * t19;
    let t255 = sqr_n(t249, 6);
    let t256 = t255 * t20;
    let t260 = sqr_n(t256, 4);
    let t261 = t260 * t5;
    let t267 = sqr_n(t261, 6);
    let t268 = t267 * t5;
    let t274 = sqr_n(t268, 6);
    let t275 = t274 * t7;
    let t283 = sqr_n(t275, 8);
    let t284 = t283 * t20;
    let t287 = sqr_n(t284, 3);
    let t288 = t287 * t3;
    let t296 = sqr_n(t288, 8);
    let t297 = t296 * t12;
    let t300 = sqr_n(t297, 3);
    let t301 = t300 * t3;
    let t309 = sqr_n(t301, 8);
    let t310 = t309 * t3;
    let t320 = sqr_n(t310, 10);
    let t321 = t320 * t21;
    let t326 = sqr_n(t321, 5);
    let t327 = t326 * t9;
    let t333 = sqr_n(t327, 6);
    let t334 = t333 * t13;
    let t339 = sqr_n(t334, 5);
    let t340 = t339 * t16;
    let t346 = sqr_n(t340, 6);
    let t347 = t346 * t9;
    let t353 = sqr_n(t347, 6);
    let t354 = t353 * t14;
    let t360 = sqr_n(t354, 6);
    let t361 = t360 * t15;
    let t366 = sqr_n(t361, 5);
    let t367 = t366 * t13;
    let t373 = sqr_n(t367, 6);
    let t374 = t373 * t10;
    let t380 = sqr_n(t374, 6);
    let t381 = t380 * t15;
    let t386 = sqr_n(t381, 5);
    let t387 = t386 * t15;
    let t393 = sqr_n(t387, 6);
    let t394 = t393 * t10;
    let t403 = sqr_n(t394, 9);
    let t404 = t403 * t21;
    let t411 = sqr_n(t404, 7);
    let t412 = t411 * t10;
    let t416 = sqr_n(t412, 4);
    let t417 = t416 * t2;
    let t425 = sqr_n(t417, 8);
    let t426 = t425 * t5;
    let t431 = sqr_n(t426, 5);
    let t432 = t431 * t8;
    let t438 = sqr_n(t432, 6);
    let t439 = t438 * t4;
    let t444 = sqr_n(t439, 5);
    let t445 = t444 * t8;
    let t453 = sqr_n(t445, 8);
    let t454 = t453 * x;
    let t462 = sqr_n(t454, 8);
    let t463 = t462 * t15;
    let t468 = sqr_n(t463, 5);
    let t469 = t468 * t7;
    let t475 = sqr_n(t469, 6);
    let t476 = t475 * t2;
    let t485 = sqr_n(t476, 9);
    let t486 = t485 * t13;
    let t491 = sqr_n(t486, 5);
    let t492 = t491 * t13;
    let t498 = sqr_n(t492, 6);
    let t499 = t498 * t2;
    let t505 = sqr_n(t499, 6);
    let t506 = t505 * t2;
    let t515 = sqr_n(t506, 9);
    let t516 = t515 * t12;
    let t523 = sqr_n(t516, 7);
    let t524 = t523 * t8;
    let t527 = sqr_n(t524, 3);
    let t528 = t527 * t2;
    let t536 = sqr_n(t528, 8);
    let t537 = t536 * t21;
    let t544 = sqr_n(t537, 7);
    let t545 = t544 * t12;
    let t547 = sqr_n(t545, 2);
    let t548 = t547 * x;
    let t556 = sqr_n(t548, 8);
    let t557 = t556 * t6;
    let t561 = sqr_n(t557, 4);
    let t562 = t561 * t3;
    let t569 = sqr_n(t562, 7);
    let t570 = t569 * t4;
    let t578 = sqr_n(t570, 8);
    let t579 = t578 * t5;
    let t586 = sqr_n(t579, 7);
    let t587 = t586 * t7;
    let t597 = sqr_n(t587, 10);
    let t598 = t597 * t5;
    let t604 = sqr_n(t598, 6);
    let t605 = t604 * t6;
    let t611 = sqr_n(t605, 6);
    let t612 = t611 * t7;
    let t618 = sqr_n(t612, 6);
    let t619 = t618 * t16;
    let t624 = sqr_n(t619, 5);
    let t625 = t624 * t13;
    let t632 = sqr_n(t625, 7);
    let t633 = t632 * t8;
    let t638 = sqr_n(t633, 5);
    let t639 = t638 * t7;
    let t646 = sqr_n(t639, 7);
    let t647 = t646 * t16;
    let t652 = sqr_n(t647, 5);
    let t653 = t652 * t4;
    let t661 = sqr_n(t653, 8);
    let t662 = t661 * t14;
    let t668 = sqr_n(t662, 6);
    let t669 = t668 * t15;
    let t675 = sqr_n(t669, 6);
    let t676 = t675 * t2;
    let t683 = sqr_n(t676, 7);
    let t684 = t683 * t6;
    let t691 = sqr_n(t684, 7);
    let t692 = t691 * t6;
    let t698 = sqr_n(t692, 6);
    let t699 = t698 * t2;
    let t704 = sqr_n(t699, 5);
    let t705 = t704 * t4;
    let t715 = sqr_n(t705, 10);
    let t716 = t715 * t14;
    let t725 = sqr_n(t716, 9);
    let t726 = t725 * t17;
    let t735 = sqr_n(t726, 9);
    let t736 = t735 * t20;
    let t742 = sqr_n(t736, 6);
    let t743 = t742 * t20;
    let t748 = sqr_n(t743, 5);
    let t749 = t748 * t15;
    let t755 = sqr_n(t749, 6);
    let t756 = t755 * t16;
    let t763 = sqr_n(t756, 7);
    let t764 = t763 * t15;
    let t769 = sqr_n(t764, 5);
    let t770 = t769 * t11;
    let t775 = sqr_n(t770, 5);
    let t776 = t775 * t11;
    let t782 = sqr_n(t776, 6);
    let t783 = t782 * t18;
    let t788 = sqr_n(t783, 5);
    let t789 = t788 * t11;
    let t794 = sqr_n(t789, 5);
    let t795 = t794 * t14;
    let t801 = sqr_n(t795, 6);
    let t802 = t801 * t4;
    let t812 = sqr_n(t802, 10);
    let t813 = t812 * t12;
    let t819 = sqr_n(t813, 6);
    let t820 = t819 * t11;
    let t826 = sqr_n(t820, 6);
    let t827 = t826 * t13;
    let t833 = sqr_n(t827, 6);
    let t834 = t833 * t7;
    let t840 = sqr_n(t834, 6);
    let t841 = t840 * t11;
    let t864 = sqr_n(t841, 23);
    let t865 = t864 * t4;
    let t871 = sqr_n(t865, 6);
    let t872 = t871 * t4;
    let t877 = sqr_n(t872, 5);
    let t878 = t877 * t2;
    let t884 = sqr_n(t878, 6);
    let t885 = t884 * t4;
    let t890 = sqr_n(t885, 5);
    t890 * t2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fp2::Fp2;

    #[cfg(feature = "experimental")]
    const P_SQUARED_MINUS9_OVER16: [u64; 12] = [
        0xb26a_a000_01c7_18e3,
        0xd7ce_d6b1_d763_82ea,
        0x3162_c338_3621_13cf,
        0x966b_f91e_d3e7_1b74,
        0xb292_e85a_8709_1a04,
        0x11d6_8619_c861_85c7,
        0xef53_1493_3097_8ef0,
        0x050a_62cf_d16d_dca6,
        0x466e_59e4_9349_e8bd,
        0x9e2d_c90e_50e7_046b,
        0x74bd_278e_aa22_f25e,
        0x002a_437a_4b8c_35fc,
    ];

    #[cfg(feature = "experimental")]
    #[test]
    fn test_pow_by_p_squared_minus9_over16() {
        use rand_core::SeedableRng;

        const SEED: [u8; 16] = [
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ];

        let mut rng = rand_xorshift::XorShiftRng::from_seed(SEED);
        for _ in 0..32 {
            let input = Fp2::try_random(&mut rng).unwrap();
            assert_eq!(
                pow_by_p_squared_minus9_over16(&input),
                input.pow_vartime_extended(&P_SQUARED_MINUS9_OVER16),
            );
        }
    }
}
