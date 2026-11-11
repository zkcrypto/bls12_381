use crate::fp::Fp;

#[inline(always)]
fn sqr_n(x: Fp, n: usize) -> Fp {
    (0..n).fold(x, |x, _| x.square())
}

#[cfg(feature = "experimental")]
impl_pow_by_p_minus3_over4!(Fp);

/// Addition chain for `(p + 1) / 4`.
///
/// Generated with `addchain 0.3.1` (381 squarings and 71 multiplications;
/// `pow_vartime` over the same constant costs 384 squarings and 229 multiplications).
#[inline(always)]
pub(crate) fn pow_by_p_plus1_over4(x: &Fp) -> Fp {
    let t1 = x.square();
    let t2 = t1.square();
    let t3 = t2 * t1;
    let t4 = t3 * x;
    let t5 = t2.square();
    let t6 = t4 * t1;
    let t7 = t4 * t2;
    let t8 = t3.square();
    let t9 = t4 * t3;
    let t10 = t4.square();
    let t11 = t6 * t5;
    let t12 = t7 * t6;
    let t13 = t8 * t6;
    let t14 = t9 * t8;
    let t15 = t9.square();
    let t16 = t14.square();
    let t17 = t15.square();
    let t18 = t16 * t14;
    let t19 = t17 * t14;
    let t20 = t18 * t2;
    let t21 = t19 * t15;
    let t22 = t17.square();
    let t23 = t20 * t15;
    let t24 = t23 * t10;
    let t25 = t21 * t12;
    let t26 = t25 * t10;
    let t27 = t25 * t15;
    let t28 = t26 * t10;
    let t29 = t24 * t17;
    let t30 = t29 * t12;
    let t31 = t30 * t2;
    let t32 = t22.square();
    let t33 = t31 * t12;
    let t34 = t29 * t16;
    let t35 = t32 * t11;
    let t36 = t33 * t12;
    let t37 = t30 * t17;
    let t38 = t31 * t16;
    let t39 = t28 * t22;
    let t48 = sqr_n(t32, 9);
    let t49 = t48 * t11;
    let t60 = sqr_n(t49, 11);
    let t61 = t60 * t38;
    let t67 = sqr_n(t61, 6);
    let t68 = t67 * t4;
    let t78 = sqr_n(t68, 10);
    let t79 = t78 * t30;
    let t87 = sqr_n(t79, 8);
    let t88 = t87 * t37;
    let t96 = sqr_n(t88, 8);
    let t97 = t96 * t19;
    let t106 = sqr_n(t97, 9);
    let t107 = t106 * t18;
    let t118 = sqr_n(t107, 11);
    let t119 = t118 * t34;
    let t128 = sqr_n(t119, 9);
    let t129 = t128 * t25;
    let t135 = sqr_n(t129, 6);
    let t136 = t135 * t14;
    let t147 = sqr_n(t136, 11);
    let t148 = t147 * t23;
    let t157 = sqr_n(t148, 9);
    let t158 = t157 * t36;
    let t168 = sqr_n(t158, 10);
    let t169 = t168 * t33;
    let t175 = sqr_n(t169, 6);
    let t176 = t175 * t14;
    let t186 = sqr_n(t176, 10);
    let t187 = t186 * t24;
    let t196 = sqr_n(t187, 9);
    let t197 = t196 * t28;
    let t208 = sqr_n(t197, 11);
    let t209 = t208 * t20;
    let t219 = sqr_n(t209, 10);
    let t220 = t219 * t35;
    let t229 = sqr_n(t220, 9);
    let t230 = t229 * t26;
    let t239 = sqr_n(t230, 9);
    let t240 = t239 * t30;
    let t248 = sqr_n(t240, 8);
    let t249 = t248 * t21;
    let t259 = sqr_n(t249, 10);
    let t260 = t259 * t31;
    let t269 = sqr_n(t260, 9);
    let t270 = t269 * t27;
    let t282 = sqr_n(t270, 12);
    let t283 = t282 * t25;
    let t288 = sqr_n(t283, 5);
    let t289 = t288 * t7;
    let t300 = sqr_n(t289, 11);
    let t301 = t300 * t25;
    let t308 = sqr_n(t301, 7);
    let t309 = t308 * t6;
    let t322 = sqr_n(t309, 13);
    let t323 = t322 * t38;
    let t332 = sqr_n(t323, 9);
    let t333 = t332 * t30;
    let t341 = sqr_n(t333, 8);
    let t342 = t341 * t39;
    let t350 = sqr_n(t342, 8);
    let t351 = t350 * t36;
    let t359 = sqr_n(t351, 8);
    let t360 = t359 * t13;
    let t370 = sqr_n(t360, 10);
    let t371 = t370 * t39;
    let t379 = sqr_n(t371, 8);
    let t380 = t379 * t39;
    let t387 = sqr_n(t380, 7);
    let t388 = t387 * t24;
    let t398 = sqr_n(t388, 10);
    let t399 = t398 * t39;
    let t408 = sqr_n(t399, 9);
    let t409 = t408 * t39;
    let t417 = sqr_n(t409, 8);
    let t418 = t417 * t39;
    let t426 = sqr_n(t418, 8);
    let t427 = t426 * t39;
    let t435 = sqr_n(t427, 8);
    let t436 = t435 * t39;
    let t441 = sqr_n(t436, 5);
    let t442 = t441 * t13;
    let t451 = sqr_n(t442, 9);
    t451 * t29
}

/// Addition chain for `p - 2`.
///
/// Generated with `addchain 0.3.1` (382 squarings and 73 multiplications;
/// `pow_vartime` over the same constant costs 384 squarings and 229 multiplications).
#[inline(always)]
pub(crate) fn pow_by_p_minus2(x: &Fp) -> Fp {
    let t1 = x.square();
    let t2 = t1.square();
    let t3 = t2.square();
    let t4 = t3 * x;
    let t5 = t3 * t1;
    let t6 = t4 * t1;
    let t7 = t3 * t2;
    let t8 = t4 * t2;
    let t9 = t5 * t2;
    let t10 = t4 * t3;
    let t11 = t5.square();
    let t12 = t6.square();
    let t13 = t8 * t7;
    let t14 = t8.square();
    let t15 = t10 * t8;
    let t16 = t14.square();
    let t17 = t15 * t13;
    let t18 = t16 * t13;
    let t19 = t18 * t1;
    let t20 = t17 * t15;
    let t21 = t19 * t9;
    let t22 = t18 * t14;
    let t23 = t16.square();
    let t24 = t19 * t14;
    let t25 = t21 * t14;
    let t26 = t21 * t15;
    let t27 = t20 * t16;
    let t28 = t25 * t15;
    let t29 = t27 * t9;
    let t30 = t28 * t11;
    let t31 = t29 * t14;
    let t32 = t30 * t12;
    let t33 = t30 * t14;
    let t34 = t23.square();
    let t35 = t33 * t11;
    let t36 = t33 * t15;
    let t37 = t31 * t16;
    let t38 = t35 * t11;
    let t39 = t35 * t15;
    let t40 = t29 * t23;
    let t49 = sqr_n(t34, 9);
    let t50 = t49 * t10;
    let t61 = sqr_n(t50, 11);
    let t62 = t61 * t39;
    let t73 = sqr_n(t62, 11);
    let t74 = t73 * t37;
    let t82 = sqr_n(t74, 8);
    let t83 = t82 * t40;
    let t90 = sqr_n(t83, 7);
    let t91 = t90 * t18;
    let t100 = sqr_n(t91, 9);
    let t101 = t100 * t24;
    let t111 = sqr_n(t101, 10);
    let t112 = t111 * t31;
    let t119 = sqr_n(t112, 7);
    let t120 = t119 * t21;
    let t129 = sqr_n(t120, 9);
    let t130 = t129 * t26;
    let t136 = sqr_n(t130, 6);
    let t137 = t136 * t13;
    let t148 = sqr_n(t137, 11);
    let t149 = t148 * t24;
    let t158 = sqr_n(t149, 9);
    let t159 = t158 * t38;
    let t169 = sqr_n(t159, 10);
    let t170 = t169 * t35;
    let t176 = sqr_n(t170, 6);
    let t177 = t176 * t13;
    let t187 = sqr_n(t177, 10);
    let t188 = t187 * t25;
    let t197 = sqr_n(t188, 9);
    let t198 = t197 * t29;
    let t209 = sqr_n(t198, 11);
    let t210 = t209 * t19;
    let t220 = sqr_n(t210, 10);
    let t221 = t220 * t36;
    let t230 = sqr_n(t221, 9);
    let t231 = t230 * t27;
    let t240 = sqr_n(t231, 9);
    let t241 = t240 * t32;
    let t249 = sqr_n(t241, 8);
    let t250 = t249 * t22;
    let t260 = sqr_n(t250, 10);
    let t261 = t260 * t33;
    let t270 = sqr_n(t261, 9);
    let t271 = t270 * t28;
    let t283 = sqr_n(t271, 12);
    let t284 = t283 * t26;
    let t289 = sqr_n(t284, 5);
    let t290 = t289 * t6;
    let t301 = sqr_n(t290, 11);
    let t302 = t301 * t26;
    let t309 = sqr_n(t302, 7);
    let t310 = t309 * t4;
    let t323 = sqr_n(t310, 13);
    let t324 = t323 * t39;
    let t333 = sqr_n(t324, 9);
    let t334 = t333 * t32;
    let t342 = sqr_n(t334, 8);
    let t343 = t342 * t40;
    let t351 = sqr_n(t343, 8);
    let t352 = t351 * t38;
    let t363 = sqr_n(t352, 11);
    let t364 = t363 * t30;
    let t372 = sqr_n(t364, 8);
    let t373 = t372 * t40;
    let t381 = sqr_n(t373, 8);
    let t382 = t381 * t40;
    let t388 = sqr_n(t382, 6);
    let t389 = t388 * t17;
    let t399 = sqr_n(t389, 10);
    let t400 = t399 * t40;
    let t409 = sqr_n(t400, 9);
    let t410 = t409 * t40;
    let t418 = sqr_n(t410, 8);
    let t419 = t418 * t40;
    let t427 = sqr_n(t419, 8);
    let t428 = t427 * t40;
    let t436 = sqr_n(t428, 8);
    let t437 = t436 * t40;
    let t444 = sqr_n(t437, 7);
    let t445 = t444 * t20;
    let t454 = sqr_n(t445, 9);
    t454 * t30
}

#[cfg(test)]
mod tests {
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

    const P_PLUS1_OVER4: [u64; 6] = [
        0xee7f_bfff_ffff_eaab,
        0x07aa_ffff_ac54_ffff,
        0xd9cc_34a8_3dac_3d89,
        0xd91d_d2e1_3ce1_44af,
        0x92c6_e9ed_90d2_eb35,
        0x0680_447a_8e5f_f9a6,
    ];

    const P_MINUS2: [u64; 6] = [
        0xb9fe_ffff_ffff_aaa9,
        0x1eab_fffe_b153_ffff,
        0x6730_d2a0_f6b0_f624,
        0x6477_4b84_f385_12bf,
        0x4b1b_a7b6_434b_acd7,
        0x1a01_11ea_397f_e69a,
    ];

    const TEST_ELEMENTS: [Fp; 4] = [
        Fp::zero(),
        Fp::one(),
        Fp::one().neg(),
        Fp::one().add(&Fp::one()).square(),
    ];
    #[cfg(feature = "experimental")]
    #[test]
    fn test_pow_by_p_minus3_over4() {
        test_chain!(Fp, &TEST_ELEMENTS, pow_by_p_minus3_over4, &P_MINUS3_OVER4);
    }

    #[test]
    fn test_pow_by_p_plus1_over4() {
        test_chain!(Fp, &TEST_ELEMENTS, pow_by_p_plus1_over4, &P_PLUS1_OVER4);
    }

    #[test]
    fn test_pow_by_p_minus2() {
        test_chain!(Fp, &TEST_ELEMENTS, pow_by_p_minus2, &P_MINUS2);
    }
}
