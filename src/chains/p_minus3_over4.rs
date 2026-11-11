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
        /// Generated with `kwantam/addchain` using Bos-Coster (win=4) (458 links, 16
        /// variables; 377 squarings and 80 multiplications; `pow_vartime` over the same
        /// constant costs 384 squarings and 228 multiplications).
        #[inline(always)]
        pub(crate) fn pow_by_p_minus3_over4(x: &$field) -> $field {
            let t1 = x.square();
            let t2 = t1 * x;
            let t3 = t1.square();
            let t4 = t2 * t1;
            let t5 = t3 * t2;
            let t6 = t4 * t3;
            let t7 = t5 * t3;
            let t8 = t6 * t3;
            let t9 = t7 * t3;
            let t10 = t8 * t3;
            let t11 = t9 * t3;
            let t12 = t10 * t3;
            let t13 = t11 * t3;
            let t14 = t8.square();
            let t15 = t13 * t3;
            let t16 = t14 * t2;
            let t17 = t14 * t4;
            let t29 = sqr_n(t14, 12);
            let t30 = t29 * t10;
            let t37 = sqr_n(t30, 7);
            let t38 = t37 * t9;
            let t42 = sqr_n(t38, 4);
            let t43 = t42 * t4;
            let t49 = sqr_n(t43, 6);
            let t50 = t49 * t5;
            let t57 = sqr_n(t50, 7);
            let t58 = t57 * t13;
            let t63 = sqr_n(t58, 5);
            let t64 = t63 * t17;
            let t66 = sqr_n(t64, 2);
            let t67 = t66 * t2;
            let t73 = sqr_n(t67, 6);
            let t74 = t73 * t8;
            let t80 = sqr_n(t74, 6);
            let t81 = t80 * t8;
            let t87 = sqr_n(t81, 6);
            let t88 = t87 * t6;
            let t91 = sqr_n(t88, 3);
            let t92 = t91 * t2;
            let t99 = sqr_n(t92, 7);
            let t100 = t99 * t8;
            let t104 = sqr_n(t100, 4);
            let t105 = t104 * t8;
            let t111 = sqr_n(t105, 6);
            let t112 = t111 * t9;
            let t118 = sqr_n(t112, 6);
            let t119 = t118 * t15;
            let t122 = sqr_n(t119, 3);
            let t123 = t122 * x;
            let t131 = sqr_n(t123, 8);
            let t132 = t131 * t8;
            let t139 = sqr_n(t132, 7);
            let t140 = t139 * t13;
            let t145 = sqr_n(t140, 5);
            let t146 = t145 * t7;
            let t152 = sqr_n(t146, 6);
            let t153 = t152 * t8;
            let t159 = sqr_n(t153, 6);
            let t160 = t159 * t16;
            let t164 = sqr_n(t160, 4);
            let t165 = t164 * t6;
            let t173 = sqr_n(t165, 8);
            let t174 = t173 * t16;
            let t178 = sqr_n(t174, 4);
            let t179 = t178 * t8;
            let t186 = sqr_n(t179, 7);
            let t187 = t186 * t13;
            let t196 = sqr_n(t187, 9);
            let t197 = t196 * t11;
            let t199 = sqr_n(t197, 2);
            let t200 = t199 * t2;
            let t205 = sqr_n(t200, 5);
            let t206 = t205 * t5;
            let t213 = sqr_n(t206, 7);
            let t214 = t213 * t4;
            let t221 = sqr_n(t214, 7);
            let t222 = t221 * t6;
            let t228 = sqr_n(t222, 6);
            let t229 = t228 * t13;
            let t234 = sqr_n(t229, 5);
            let t235 = t234 * t16;
            let t240 = sqr_n(t235, 5);
            let t241 = t240 * t11;
            let t246 = sqr_n(t241, 5);
            let t247 = t246 * t11;
            let t255 = sqr_n(t247, 8);
            let t256 = t255 * t8;
            let t263 = sqr_n(t256, 7);
            let t264 = t263 * t12;
            let t273 = sqr_n(t264, 9);
            let t274 = t273 * t9;
            let t279 = sqr_n(t274, 5);
            let t280 = t279 * t8;
            let t283 = sqr_n(t280, 3);
            let t284 = t283 * t2;
            let t292 = sqr_n(t284, 8);
            let t293 = t292 * t9;
            let t296 = sqr_n(t293, 3);
            let t297 = t296 * t2;
            let t304 = sqr_n(t297, 7);
            let t305 = t304 * t6;
            let t314 = sqr_n(t305, 9);
            let t315 = t314 * t9;
            let t321 = sqr_n(t315, 6);
            let t322 = t321 * t12;
            let t328 = sqr_n(t322, 6);
            let t329 = t328 * t17;
            let t334 = sqr_n(t329, 5);
            let t335 = t334 * t17;
            let t340 = sqr_n(t335, 5);
            let t341 = t340 * t17;
            let t345 = sqr_n(t341, 4);
            let t346 = t345 * t8;
            let t349 = sqr_n(t346, 3);
            let t350 = t349 * t2;
            let t358 = sqr_n(t350, 8);
            let t359 = t358 * t12;
            let t366 = sqr_n(t359, 7);
            let t367 = t366 * t17;
            let t372 = sqr_n(t367, 5);
            let t373 = t372 * t17;
            let t378 = sqr_n(t373, 5);
            let t379 = t378 * t17;
            let t383 = sqr_n(t379, 4);
            let t384 = t383 * t9;
            let t388 = sqr_n(t384, 4);
            let t389 = t388 * t5;
            let t396 = sqr_n(t389, 7);
            let t397 = t396 * t17;
            let t402 = sqr_n(t397, 5);
            let t403 = t402 * t16;
            let t408 = sqr_n(t403, 5);
            let t409 = t408 * t17;
            let t414 = sqr_n(t409, 5);
            let t415 = t414 * t17;
            let t420 = sqr_n(t415, 5);
            let t421 = t420 * t17;
            let t426 = sqr_n(t421, 5);
            let t427 = t426 * t17;
            let t432 = sqr_n(t427, 5);
            let t433 = t432 * t17;
            let t438 = sqr_n(t433, 5);
            let t439 = t438 * t17;
            let t443 = sqr_n(t439, 4);
            let t444 = t443 * t8;
            let t450 = sqr_n(t444, 6);
            let t451 = t450 * t12;
            let t455 = sqr_n(t451, 4);
            let t456 = t455 * t4;
            let t457 = t456.square();
            t457
        }
    };
}
