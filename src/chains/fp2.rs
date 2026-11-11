use crate::fp2::Fp2;

#[inline(always)]
fn sqr_n(x: Fp2, n: usize) -> Fp2 {
    (0..n).fold(x, |x, _| x.square())
}

/// Addition chain for `(p² - 9) / 16`, where p is the base-field modulus.
///
/// Generated with `kwantam/addchain` using Bos-Coster (win=4) (895 links, 17 variables;
/// 754 squarings and 140 multiplications; `pow_vartime_extended` over the same constant
/// costs 768 squarings and 366 multiplications).
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
    let t19 = sqr_n(t11, 3);
    let t20 = t19 * x;
    let t29 = sqr_n(t20, 9);
    let t30 = t29 * t14;
    let t34 = sqr_n(t30, 4);
    let t35 = t34 * t7;
    let t41 = sqr_n(t35, 6);
    let t42 = t41 * t5;
    let t46 = sqr_n(t42, 4);
    let t47 = t46 * t4;
    let t52 = sqr_n(t47, 5);
    let t53 = t52 * t2;
    let t61 = sqr_n(t53, 8);
    let t62 = t61 * t7;
    let t66 = sqr_n(t62, 4);
    let t67 = t66 * t4;
    let t71 = sqr_n(t67, 4);
    let t72 = t71 * t8;
    let t80 = sqr_n(t72, 8);
    let t81 = t80 * t15;
    let t87 = sqr_n(t81, 6);
    let t88 = t87 * t6;
    let t92 = sqr_n(t88, 4);
    let t93 = t92 * t7;
    let t96 = sqr_n(t93, 3);
    let t97 = t96 * x;
    let t103 = sqr_n(t97, 6);
    let t104 = t103 * t8;
    let t112 = sqr_n(t104, 8);
    let t113 = t112 * t15;
    let t119 = sqr_n(t113, 6);
    let t120 = t119 * t11;
    let t128 = sqr_n(t120, 8);
    let t129 = t128 * t9;
    let t134 = sqr_n(t129, 5);
    let t135 = t134 * t8;
    let t141 = sqr_n(t135, 6);
    let t142 = t141 * t5;
    let t147 = sqr_n(t142, 5);
    let t148 = t147 * t8;
    let t150 = sqr_n(t148, 2);
    let t151 = t150 * x;
    let t157 = sqr_n(t151, 6);
    let t158 = t157 * t8;
    let t165 = sqr_n(t158, 7);
    let t166 = t165 * t6;
    let t170 = sqr_n(t166, 4);
    let t171 = t170 * t4;
    let t177 = sqr_n(t171, 6);
    let t178 = t177 * t5;
    let t185 = sqr_n(t178, 7);
    let t186 = t185 * t4;
    let t191 = sqr_n(t186, 5);
    let t192 = t191 * t3;
    let t199 = sqr_n(t192, 7);
    let t200 = t199 * t4;
    let t205 = sqr_n(t200, 5);
    let t206 = t205 * t4;
    let t216 = sqr_n(t206, 10);
    let t217 = t216 * t9;
    let t220 = sqr_n(t217, 3);
    let t221 = t220 * t3;
    let t226 = sqr_n(t221, 5);
    let t227 = t226 * t7;
    let t235 = sqr_n(t227, 8);
    let t236 = t235 * t13;
    let t241 = sqr_n(t236, 5);
    let t242 = t241 * t12;
    let t248 = sqr_n(t242, 6);
    let t249 = t248 * t6;
    let t255 = sqr_n(t249, 6);
    let t256 = t255 * t8;
    let t262 = sqr_n(t256, 6);
    let t263 = t262 * t5;
    let t270 = sqr_n(t263, 7);
    let t271 = t270 * t10;
    let t276 = sqr_n(t271, 5);
    let t277 = t276 * t5;
    let t283 = sqr_n(t277, 6);
    let t284 = t283 * t8;
    let t290 = sqr_n(t284, 6);
    let t291 = t290 * t9;
    let t296 = sqr_n(t291, 5);
    let t297 = t296 * t8;
    let t299 = sqr_n(t297, 2);
    let t300 = t299 * x;
    let t308 = sqr_n(t300, 8);
    let t309 = t308 * t3;
    let t316 = sqr_n(t309, 7);
    let t317 = t316 * t3;
    let t321 = sqr_n(t317, 4);
    let t322 = t321 * t2;
    let t329 = sqr_n(t322, 7);
    let t330 = t329 * t6;
    let t336 = sqr_n(t330, 6);
    let t337 = t336 * t8;
    let t341 = sqr_n(t337, 4);
    let t342 = t341 * t7;
    let t349 = sqr_n(t342, 7);
    let t350 = t349 * t6;
    let t356 = sqr_n(t350, 6);
    let t357 = t356 * t14;
    let t362 = sqr_n(t357, 5);
    let t363 = t362 * t12;
    let t368 = sqr_n(t363, 5);
    let t369 = t368 * t3;
    let t376 = sqr_n(t369, 7);
    let t377 = t376 * t14;
    let t382 = sqr_n(t377, 5);
    let t383 = t382 * t12;
    let t388 = sqr_n(t383, 5);
    let t389 = t388 * t11;
    let t393 = sqr_n(t389, 4);
    let t394 = t393 * t2;
    let t400 = sqr_n(t394, 6);
    let t401 = t400 * t3;
    let t407 = sqr_n(t401, 6);
    let t408 = t407 * t5;
    let t412 = sqr_n(t408, 4);
    let t413 = t412 * t2;
    let t417 = sqr_n(t413, 4);
    let t418 = t417 * t2;
    let t426 = sqr_n(t418, 8);
    let t427 = t426 * t5;
    let t432 = sqr_n(t427, 5);
    let t433 = t432 * t8;
    let t439 = sqr_n(t433, 6);
    let t440 = t439 * t4;
    let t445 = sqr_n(t440, 5);
    let t446 = t445 * t8;
    let t458 = sqr_n(t446, 12);
    let t459 = t458 * t9;
    let t463 = sqr_n(t459, 4);
    let t464 = t463 * t7;
    let t469 = sqr_n(t464, 5);
    let t470 = t469 * t7;
    let t476 = sqr_n(t470, 6);
    let t477 = t476 * t2;
    let t486 = sqr_n(t477, 9);
    let t487 = t486 * t13;
    let t492 = sqr_n(t487, 5);
    let t493 = t492 * t13;
    let t499 = sqr_n(t493, 6);
    let t500 = t499 * t2;
    let t506 = sqr_n(t500, 6);
    let t507 = t506 * t2;
    let t516 = sqr_n(t507, 9);
    let t517 = t516 * t12;
    let t524 = sqr_n(t517, 7);
    let t525 = t524 * t8;
    let t531 = sqr_n(t525, 6);
    let t532 = t531 * t13;
    let t537 = sqr_n(t532, 5);
    let t538 = t537 * t5;
    let t545 = sqr_n(t538, 7);
    let t546 = t545 * t12;
    let t548 = sqr_n(t546, 2);
    let t549 = t548 * x;
    let t557 = sqr_n(t549, 8);
    let t558 = t557 * t6;
    let t562 = sqr_n(t558, 4);
    let t563 = t562 * t3;
    let t570 = sqr_n(t563, 7);
    let t571 = t570 * t4;
    let t579 = sqr_n(t571, 8);
    let t580 = t579 * t5;
    let t587 = sqr_n(t580, 7);
    let t588 = t587 * t7;
    let t598 = sqr_n(t588, 10);
    let t599 = t598 * t5;
    let t605 = sqr_n(t599, 6);
    let t606 = t605 * t6;
    let t612 = sqr_n(t606, 6);
    let t613 = t612 * t7;
    let t619 = sqr_n(t613, 6);
    let t620 = t619 * t16;
    let t625 = sqr_n(t620, 5);
    let t626 = t625 * t13;
    let t633 = sqr_n(t626, 7);
    let t634 = t633 * t8;
    let t639 = sqr_n(t634, 5);
    let t640 = t639 * t7;
    let t647 = sqr_n(t640, 7);
    let t648 = t647 * t16;
    let t653 = sqr_n(t648, 5);
    let t654 = t653 * t4;
    let t662 = sqr_n(t654, 8);
    let t663 = t662 * t14;
    let t669 = sqr_n(t663, 6);
    let t670 = t669 * t15;
    let t676 = sqr_n(t670, 6);
    let t677 = t676 * t2;
    let t684 = sqr_n(t677, 7);
    let t685 = t684 * t6;
    let t692 = sqr_n(t685, 7);
    let t693 = t692 * t6;
    let t699 = sqr_n(t693, 6);
    let t700 = t699 * t2;
    let t705 = sqr_n(t700, 5);
    let t706 = t705 * t4;
    let t716 = sqr_n(t706, 10);
    let t717 = t716 * t14;
    let t721 = sqr_n(t717, 4);
    let t722 = t721 * x;
    let t731 = sqr_n(t722, 9);
    let t732 = t731 * t9;
    let t738 = sqr_n(t732, 6);
    let t739 = t738 * t8;
    let t746 = sqr_n(t739, 7);
    let t747 = t746 * t16;
    let t752 = sqr_n(t747, 5);
    let t753 = t752 * t11;
    let t757 = sqr_n(t753, 4);
    let t758 = t757 * t8;
    let t765 = sqr_n(t758, 7);
    let t766 = t765 * t15;
    let t771 = sqr_n(t766, 5);
    let t772 = t771 * t11;
    let t777 = sqr_n(t772, 5);
    let t778 = t777 * t11;
    let t783 = sqr_n(t778, 5);
    let t784 = t783 * t9;
    let t788 = sqr_n(t784, 4);
    let t789 = t788 * t7;
    let t795 = sqr_n(t789, 6);
    let t796 = t795 * t15;
    let t797 = t796.square();
    let t798 = t797 * x;
    let t804 = sqr_n(t798, 6);
    let t805 = t804 * t4;
    let t815 = sqr_n(t805, 10);
    let t816 = t815 * t12;
    let t822 = sqr_n(t816, 6);
    let t823 = t822 * t11;
    let t829 = sqr_n(t823, 6);
    let t830 = t829 * t13;
    let t836 = sqr_n(t830, 6);
    let t837 = t836 * t7;
    let t843 = sqr_n(t837, 6);
    let t844 = t843 * t11;
    let t867 = sqr_n(t844, 23);
    let t868 = t867 * t4;
    let t874 = sqr_n(t868, 6);
    let t875 = t874 * t4;
    let t880 = sqr_n(t875, 5);
    let t881 = t880 * t2;
    let t887 = sqr_n(t881, 6);
    let t888 = t887 * t4;
    let t893 = sqr_n(t888, 5);
    t893 * t2
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
