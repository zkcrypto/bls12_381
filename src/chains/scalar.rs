use crate::scalar::Scalar;

#[inline(always)]
fn sqr_n(x: Scalar, n: usize) -> Scalar {
    (0..n).fold(x, |x, _| x.square())
}

/// Addition chain for `q - 2`, where `q` is the scalar field modulus.
///
/// Generated with `addchain 0.3.1` (254 squarings and 46 multiplications; `pow_vartime`
/// over the same constant costs 256 squarings and 164 multiplications).
#[inline(always)]
pub(crate) fn pow_by_q_minus2(x: &Scalar) -> Scalar {
    let t1 = x.square();
    let t2 = t1.square();
    let t3 = t2.square();
    let t4 = t3 * x;
    let t5 = t4 * t1;
    let t6 = t3.square();
    let t7 = t4.square();
    let t8 = t7 * t5;
    let t9 = t8.square();
    let t10 = t9 * x;
    let t11 = t10 * t7;
    let t12 = t11 * t3;
    let t13 = t12 * t6;
    let t14 = t12 * t7;
    let t15 = t13 * t2;
    let t16 = t10 * t9;
    let t17 = t16 * t4;
    let t18 = t11.square();
    let t19 = t14.square();
    let t20 = t18 * t12;
    let t21 = t18 * t13;
    let t22 = t18 * t14;
    let t23 = t20 * t17;
    let t24 = t21 * t17;
    let t25 = t22 * t17;
    let t26 = t21 * t18;
    let t27 = t26 * t2;
    let t28 = t22 * t19;
    let t37 = sqr_n(t28, 9);
    let t38 = t37 * t23;
    let t47 = sqr_n(t38, 9);
    let t48 = t47 * t16;
    let t57 = sqr_n(t48, 9);
    let t58 = t57 * t13;
    let t67 = sqr_n(t58, 9);
    let t68 = t67 * t14;
    let t78 = sqr_n(t68, 10);
    let t79 = t78 * t24;
    let t84 = sqr_n(t79, 5);
    let t85 = t84 * t4;
    let t99 = sqr_n(t85, 14);
    let t100 = t99 * t26;
    let t109 = sqr_n(t100, 9);
    let t110 = t109 * t27;
    let t119 = sqr_n(t110, 9);
    let t120 = t119 * t22;
    let t134 = sqr_n(t120, 14);
    let t135 = t134 * t11;
    let t145 = sqr_n(t135, 10);
    let t146 = t145 * t10;
    let t161 = sqr_n(t146, 15);
    let t162 = t161 * t12;
    let t172 = sqr_n(t162, 10);
    let t173 = t172 * t20;
    let t181 = sqr_n(t173, 8);
    let t182 = t181 * t15;
    let t199 = sqr_n(t182, 17);
    let t200 = t199 * t25;
    let t208 = sqr_n(t200, 8);
    let t209 = t208 * t21;
    let t215 = sqr_n(t209, 6);
    let t216 = t215 * t5;
    let t225 = sqr_n(t216, 9);
    let t226 = t225 * t21;
    let t235 = sqr_n(t226, 9);
    let t236 = t235 * t25;
    let t244 = sqr_n(t236, 8);
    let t245 = t244 * t21;
    let t253 = sqr_n(t245, 8);
    let t254 = t253 * t21;
    let t262 = sqr_n(t254, 8);
    let t263 = t262 * t21;
    let t272 = sqr_n(t263, 9);
    let t273 = t272 * t21;
    let t281 = sqr_n(t273, 8);
    let t282 = t281 * t21;
    let t290 = sqr_n(t282, 8);
    let t291 = t290 * t21;
    let t299 = sqr_n(t291, 8);
    t299 * t21
}

/// Addition chain for `(t - 1) / 2`.
///
/// Generated with `addchain 0.3.1` (221 squarings and 42 multiplications;
/// `pow_vartime` over the same constant costs 256 squarings and 132 multiplications).
/// `test_pow_by_t_minus1_over2` checks it against `pow_vartime`.
#[cfg(feature = "sqrt-table")]
#[inline(always)]
pub(crate) fn pow_by_t_minus1_over2(x: &Scalar) -> Scalar {
    let t1 = x.square();
    let t2 = t1.square();
    let t3 = t2.square();
    let t4 = t3 * x;
    let t5 = t4 * t1;
    let t6 = t3.square();
    let t7 = t4.square();
    let t8 = t7 * t5;
    let t9 = t8.square();
    let t10 = t9 * x;
    let t11 = t10 * t7;
    let t12 = t11 * t3;
    let t13 = t12 * t6;
    let t14 = t12 * t7;
    let t15 = t13 * t2;
    let t16 = t10 * t9;
    let t17 = t16 * t4;
    let t18 = t11.square();
    let t19 = t14.square();
    let t20 = t18 * t12;
    let t21 = t18 * t13;
    let t22 = t18 * t14;
    let t23 = t20 * t17;
    let t24 = t21 * t17;
    let t25 = t22 * t17;
    let t26 = t21 * t18;
    let t27 = t26 * t2;
    let t28 = t22 * t19;
    let t37 = sqr_n(t28, 9);
    let t38 = t37 * t23;
    let t47 = sqr_n(t38, 9);
    let t48 = t47 * t16;
    let t57 = sqr_n(t48, 9);
    let t58 = t57 * t13;
    let t67 = sqr_n(t58, 9);
    let t68 = t67 * t14;
    let t78 = sqr_n(t68, 10);
    let t79 = t78 * t24;
    let t84 = sqr_n(t79, 5);
    let t85 = t84 * t4;
    let t99 = sqr_n(t85, 14);
    let t100 = t99 * t26;
    let t109 = sqr_n(t100, 9);
    let t110 = t109 * t27;
    let t119 = sqr_n(t110, 9);
    let t120 = t119 * t22;
    let t134 = sqr_n(t120, 14);
    let t135 = t134 * t11;
    let t145 = sqr_n(t135, 10);
    let t146 = t145 * t10;
    let t161 = sqr_n(t146, 15);
    let t162 = t161 * t12;
    let t172 = sqr_n(t162, 10);
    let t173 = t172 * t20;
    let t181 = sqr_n(t173, 8);
    let t182 = t181 * t15;
    let t199 = sqr_n(t182, 17);
    let t200 = t199 * t25;
    let t208 = sqr_n(t200, 8);
    let t209 = t208 * t21;
    let t215 = sqr_n(t209, 6);
    let t216 = t215 * t5;
    let t225 = sqr_n(t216, 9);
    let t226 = t225 * t21;
    let t235 = sqr_n(t226, 9);
    let t236 = t235 * t25;
    let t244 = sqr_n(t236, 8);
    let t245 = t244 * t21;
    let t253 = sqr_n(t245, 8);
    let t254 = t253 * t21;
    let t262 = sqr_n(t254, 8);
    t262 * t21
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q_MINUS2: [u64; 4] = [
        0xffff_fffe_ffff_ffff,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ];

    #[test]
    fn test_pow_by_q_minus2() {
        for x in [
            Scalar::zero(),
            Scalar::one(),
            -Scalar::one(),
            Scalar::from(2),
            Scalar::from(42),
            Scalar::from(u64::MAX),
        ] {
            assert_eq!(pow_by_q_minus2(&x), x.pow_vartime(&Q_MINUS2));
        }
    }
}
