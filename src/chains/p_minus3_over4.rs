//! Shared addition chain for exponentiation by `(p - 3) / 4`.
//!
//! Each invocation expands to a function using the field's own multiplication
//! and squaring operations; no field abstraction or dynamic dispatch is needed.

macro_rules! impl_pow_by_p_minus3_over4 {
    ($field:ty) => {
        /// Addition chain for `(p - 3) / 4`.
        ///
        /// Here p is the base-field modulus, including when this chain is evaluated in Fp2.
        ///
        /// Generated with `addchain 0.3.1` (381 squarings and 72 multiplications;
        /// `pow_vartime` over the same constant costs 384 squarings and 228
        /// multiplications).
        #[inline(always)]
        pub(crate) fn pow_by_p_minus3_over4(x: &$field) -> $field {
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
            let t16 = t13.square();
            let t17 = t16 * t4;
            let t18 = t15.square();
            let t19 = t17 * t15;
            let t20 = t18 * t14;
            let t21 = t19 * t2;
            let t22 = t20 * t5;
            let t23 = t20 * t15;
            let t24 = t18.square();
            let t25 = t21 * t15;
            let t26 = t20 * t16;
            let t27 = t23 * t12;
            let t28 = t22 * t18;
            let t29 = t27 * t15;
            let t30 = t28 * t10;
            let t31 = t29 * t16;
            let t32 = t31 * t2;
            let t33 = t24.square();
            let t34 = t32 * t12;
            let t35 = t32 * t15;
            let t36 = t33 * t11;
            let t37 = t34 * t12;
            let t38 = t31 * t18;
            let t39 = t36 * t12;
            let t40 = t30 * t24;
            let t49 = sqr_n(t33, 9);
            let t50 = t49 * t11;
            let t61 = sqr_n(t50, 11);
            let t62 = t61 * t39;
            let t68 = sqr_n(t62, 6);
            let t69 = t68 * t4;
            let t79 = sqr_n(t69, 10);
            let t80 = t79 * t31;
            let t88 = sqr_n(t80, 8);
            let t89 = t88 * t38;
            let t97 = sqr_n(t89, 8);
            let t98 = t97 * t20;
            let t107 = sqr_n(t98, 9);
            let t108 = t107 * t19;
            let t119 = sqr_n(t108, 11);
            let t120 = t119 * t35;
            let t129 = sqr_n(t120, 9);
            let t130 = t129 * t27;
            let t136 = sqr_n(t130, 6);
            let t137 = t136 * t14;
            let t148 = sqr_n(t137, 11);
            let t149 = t148 * t25;
            let t158 = sqr_n(t149, 9);
            let t159 = t158 * t37;
            let t169 = sqr_n(t159, 10);
            let t170 = t169 * t34;
            let t176 = sqr_n(t170, 6);
            let t177 = t176 * t14;
            let t187 = sqr_n(t177, 10);
            let t188 = t187 * t26;
            let t197 = sqr_n(t188, 9);
            let t198 = t197 * t30;
            let t209 = sqr_n(t198, 11);
            let t210 = t209 * t21;
            let t220 = sqr_n(t210, 10);
            let t221 = t220 * t36;
            let t230 = sqr_n(t221, 9);
            let t231 = t230 * t28;
            let t240 = sqr_n(t231, 9);
            let t241 = t240 * t31;
            let t249 = sqr_n(t241, 8);
            let t250 = t249 * t23;
            let t260 = sqr_n(t250, 10);
            let t261 = t260 * t32;
            let t270 = sqr_n(t261, 9);
            let t271 = t270 * t29;
            let t283 = sqr_n(t271, 12);
            let t284 = t283 * t27;
            let t289 = sqr_n(t284, 5);
            let t290 = t289 * t7;
            let t301 = sqr_n(t290, 11);
            let t302 = t301 * t27;
            let t309 = sqr_n(t302, 7);
            let t310 = t309 * t6;
            let t323 = sqr_n(t310, 13);
            let t324 = t323 * t39;
            let t333 = sqr_n(t324, 9);
            let t334 = t333 * t31;
            let t342 = sqr_n(t334, 8);
            let t343 = t342 * t40;
            let t351 = sqr_n(t343, 8);
            let t352 = t351 * t37;
            let t360 = sqr_n(t352, 8);
            let t361 = t360 * t13;
            let t371 = sqr_n(t361, 10);
            let t372 = t371 * t40;
            let t380 = sqr_n(t372, 8);
            let t381 = t380 * t40;
            let t388 = sqr_n(t381, 7);
            let t389 = t388 * t26;
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
            let t442 = sqr_n(t437, 5);
            let t443 = t442 * t13;
            let t451 = sqr_n(t443, 8);
            let t452 = t451 * t22;
            let t453 = t452.square();
            t453
        }
    };
}
