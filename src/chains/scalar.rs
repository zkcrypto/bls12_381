use crate::scalar::Scalar;

#[inline(always)]
fn sqr_n(x: Scalar, n: usize) -> Scalar {
    (0..n).fold(x, |x, _| x.square())
}

/// Addition chain for `q - 2`, where `q` is the scalar field modulus.
///
/// Generated with `kwantam/addchain` (252 squarings and 52 multiplications; `pow_vartime`
/// over the same constant costs 256 squarings and 164 multiplications).
#[inline(always)]
pub(crate) fn pow_by_q_minus2(x: &Scalar) -> Scalar {
    let t1 = x.square();
    let t2 = t1 * x;
    let t3 = t1.square();
    let t4 = t3.square();
    let t5 = t4 * t1;
    let t6 = t4 * t3;
    let t7 = t5 * t3;
    let t8 = t4.square();
    let t9 = t5 * t4;
    let t10 = t6 * t5;
    let t11 = t7.square();
    let t12 = t2 * t11;
    let t13 = t9 * t8;
    let t14 = t12 * t11;
    let t15 = t14 * t8;
    let t16 = t14 * t9;
    let t17 = t15 * t5;
    let t18 = t15 * t11;
    let t19 = t16 * t11;
    let t20 = t17 * t10;
    let t21 = t18 * t7;
    let t22 = t18 * t11;
    let t23 = t10 * t22;
    let t24 = t3 * t23;
    let t25 = t13 * t24;
    let t26 = t11 * t25;
    let t27 = t6 * t26;
    let t28 = t4 * t27;
    let t29 = t8 * t28;
    let t37 = sqr_n(t27, 8);
    let t38 = t37 * t26;
    let t47 = sqr_n(t38, 9);
    let t48 = t47 * t24;
    let t57 = sqr_n(t48, 9);
    let t58 = t57 * t23;
    let t67 = sqr_n(t58, 9);
    let t68 = t67 * t23;
    let t75 = sqr_n(t68, 7);
    let t76 = t75 * t20;
    let t83 = sqr_n(t76, 7);
    let t84 = t83 * t21;
    let t94 = sqr_n(t84, 10);
    let t95 = t94 * t22;
    let t104 = sqr_n(t95, 9);
    let t105 = t104 * t18;
    let t113 = sqr_n(t105, 8);
    let t114 = t113 * t14;
    let t122 = sqr_n(t114, 8);
    let t123 = t122 * x;
    let t137 = sqr_n(t123, 14);
    let t138 = t137 * t16;
    let t148 = sqr_n(t138, 10);
    let t149 = t148 * t14;
    let t164 = sqr_n(t149, 15);
    let t165 = t164 * t17;
    let t175 = sqr_n(t165, 10);
    let t176 = t175 * t28;
    let t184 = sqr_n(t176, 8);
    let t185 = t184 * t19;
    let t201 = sqr_n(t185, 16);
    let t202 = t201 * t25;
    let t210 = sqr_n(t202, 8);
    let t211 = t210 * t29;
    let t218 = sqr_n(t211, 7);
    let t219 = t218 * t15;
    let t228 = sqr_n(t219, 9);
    let t229 = t228 * t29;
    let t237 = sqr_n(t229, 8);
    let t238 = t237 * t25;
    let t246 = sqr_n(t238, 8);
    let t247 = t246 * t29;
    let t255 = sqr_n(t247, 8);
    let t256 = t255 * t29;
    let t264 = sqr_n(t256, 8);
    let t265 = t264 * t29;
    let t273 = sqr_n(t265, 8);
    let t274 = t273 * t25;
    let t282 = sqr_n(t274, 8);
    let t283 = t282 * t29;
    let t291 = sqr_n(t283, 8);
    let t292 = t291 * t29;
    let t297 = sqr_n(t292, 5);
    let t298 = t297 * t12;
    let t303 = sqr_n(t298, 5);
    t303 * t12
}

/// Addition chain for `(t - 1) / 2`.
///
/// Generated with `mmcloughlin/addchain v0.4.0` (217 squarings and 47 multiplications;
/// `pow_vartime` over the same constant costs 256 squarings and 132 multiplications).
/// `test_pow_by_t_minus1_over2` checks it against `pow_vartime`.
#[cfg(feature = "sqrt-table")]
#[inline(always)]
pub(crate) fn pow_by_t_minus1_over2(x: &Scalar) -> Scalar {
    let x1 = *x;
    let x10 = x1.square();
    let x100 = x10.square();
    let x110 = x10 * x100;
    let x1100 = x110.square();
    let x10010 = x110 * x1100;
    let x10011 = x1 * x10010;
    let x10110 = x100 * x10010;
    let x11000 = x10 * x10110;
    let x11010 = x10 * x11000;
    let x100010 = x1100 * x10110;
    let x110101 = x10011 * x100010;
    let x111011 = x110 * x110101;
    let x1001011 = x10110 * x110101;
    let x1001101 = x10 * x1001011;
    let x1010101 = x11010 * x111011;
    let x1100111 = x10010 * x1010101;
    let x1101001 = x10 * x1100111;
    let x10000011 = x11010 * x1101001;
    let x10011001 = x10110 * x10000011;
    let x10011101 = x100 * x10011001;
    let x10111111 = x100010 * x10011101;
    let x11010111 = x11000 * x10111111;
    let x11011011 = x100 * x11010111;
    let x11100111 = x1100 * x11011011;
    let x11101111 = x11000 * x11010111;
    let x11111111 = x11000 * x11100111;
    let i54 = sqr_n(sqr_n(sqr_n(x11100111, 8) * x11011011, 9) * x10011101, 9);
    let i74 = sqr_n(sqr_n(x10011001 * i54, 9) * x10011001, 8) * x11010111;
    let i101 = sqr_n(sqr_n(sqr_n(i74, 6) * x110101, 10) * x10000011, 9);
    let i120 = sqr_n(sqr_n(x1100111 * i101, 8) * x111011, 8) * x1;
    let i161 = sqr_n(sqr_n(sqr_n(i120, 14) * x1001101, 10) * x111011, 15);
    let i182 = sqr_n(sqr_n(x1010101 * i161, 10) * x11101111, 8) * x1101001;
    let i215 = sqr_n(sqr_n(sqr_n(i182, 16) * x10111111, 8) * x11111111, 7);
    let i235 = sqr_n(sqr_n(x1001011 * i215, 9) * x11111111, 8) * x10111111;
    let i261 = sqr_n(sqr_n(sqr_n(i235, 8) * x11111111, 8) * x11111111, 8);
    (x11111111 * i261).square() * x1
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
