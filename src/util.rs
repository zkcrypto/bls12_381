use crypto_bigint::{Limb, UInt, Word};

#[inline(always)]
pub const fn uint_reduction_inv<const LIMBS: usize>(modulus: &UInt<LIMBS>) -> Limb {
    modulus
        .inv_mod2k(Word::BITS as usize)
        .neg_mod(&UInt::ONE.shl_vartime(Word::BITS as usize))
        .limbs()[0]
}

/// The Montgomery reduction here is based on Algorithm 14.32 in
/// Handbook of Applied Cryptography
/// <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.
#[inline(always)]
pub const fn uint_montgomery_reduce<const LIMBS: usize>(
    lo: UInt<LIMBS>,
    hi: UInt<LIMBS>,
    modulus: &UInt<LIMBS>,
    inv: Limb,
) -> UInt<LIMBS> {
    let mod_words = modulus.limbs();
    let hi_words = hi.limbs();
    let mut limbs = lo.into_limbs();

    let mut carry = Limb::ZERO;
    let mut i = 0;
    while i < LIMBS {
        let k = limbs[0].wrapping_mul(inv);

        let (_, c) = limbs[0].mac(k, mod_words[0], Limb::ZERO);
        let mut carry2 = c;

        let mut j = 1;
        while j < LIMBS {
            let (l, c) = limbs[j].mac(k, mod_words[j], carry2);
            limbs[j - 1] = l;
            carry2 = c;
            j += 1;
        }

        let (l, c) = hi_words[i].adc(carry, carry2);
        limbs[j - 1] = l;
        carry = c;

        i += 1;
    }

    // Final conditional subtraction to ensure the output is in range.
    uint_try_sub(&UInt::new(limbs), modulus)
}

/// Multiplies two elements
#[inline(always)]
pub const fn uint_mul_mod<const LIMBS: usize>(
    lhs: &UInt<LIMBS>,
    rhs: &UInt<LIMBS>,
    modulus: &UInt<LIMBS>,
    inv: Limb,
) -> UInt<LIMBS> {
    let (lo, hi) = lhs.mul_wide(&rhs);
    uint_montgomery_reduce(lo, hi, modulus, inv)
}

/// Squares an element
#[inline(always)]
pub const fn uint_square<const LIMBS: usize>(uint: &UInt<LIMBS>) -> (UInt<LIMBS>, UInt<LIMBS>) {
    let limbs = uint.limbs();
    let mut lo = [Limb::ZERO; LIMBS];
    let mut hi = [Limb::ZERO; LIMBS];
    let mut i = 0;
    while i < LIMBS - 1 {
        let mut j = i;
        let mut carry = Limb::ZERO;

        while j < LIMBS - 1 {
            let k = i + j;
            if k >= LIMBS {
                let (n, c) = hi[k - LIMBS].mac(limbs[i], limbs[j + 1], carry);
                hi[k - LIMBS] = n;
                carry = c;
            } else {
                let (n, c) = lo[k].mac(limbs[i], limbs[j + 1], carry);
                lo[k] = n;
                carry = c;
            }
            j += 1;
        }

        if i == 0 {
            lo[LIMBS - 1] = carry;
        } else {
            hi[i - 1] = carry;
        }
        i += 1;
    }

    // Shift [hi || lo] to the left
    // (Slightly complicated by Limb not implementing shl)
    hi[LIMBS - 1] = Limb(hi[LIMBS - 2].0 >> (Limb::BIT_SIZE - 1));
    let mut i = LIMBS - 2;
    while i > 0 {
        hi[i] = Limb((hi[i].0 << 1) | (hi[i - 1].0 >> (Limb::BIT_SIZE - 1)));
        i -= 1;
    }
    hi[0] = Limb((hi[0].0 << 1) | (lo[LIMBS - 1].0 >> (Limb::BIT_SIZE - 1)));
    let mut i = LIMBS - 1;
    while i > 0 {
        lo[i] = Limb((lo[i].0 << 1) | (lo[i - 1].0 >> (Limb::BIT_SIZE - 1)));
        i -= 1;
    }
    lo[0] = Limb(lo[0].0 << 1);

    let mut i = 0;
    let mut base = Limb::ZERO;
    let mut carry = Limb::ZERO;
    while i < LIMBS {
        let (l1, c) = base.mac(limbs[i], limbs[i], carry);
        let k = i * 2;
        if k >= LIMBS {
            let (l2, c) = hi[k - LIMBS].adc(Limb::ZERO, c);
            hi[k - LIMBS] = l1;
            base = hi[k - LIMBS + 1];
            hi[k - LIMBS + 1] = l2;
            carry = c;
        } else {
            let (l2, c) = lo[k].adc(Limb::ZERO, c);
            lo[k] = l1;
            base = lo[k + 1];
            lo[k + 1] = l2;
            carry = c;
        };
        i += 1;
    }

    (UInt::new(lo), UInt::new(hi))
}

/// Squares an element
#[inline(always)]
pub const fn uint_square_mod<const LIMBS: usize>(
    uint: &UInt<LIMBS>,
    modulus: &UInt<LIMBS>,
    inv: Limb,
) -> UInt<LIMBS> {
    let (lo, hi) = uint_square(&uint);
    uint_montgomery_reduce(lo, hi, modulus, inv)
}

/// Although this is labeled "vartime", it is only
/// variable time with respect to the exponent.
pub const fn uint_pow_vartime<const LIMBS: usize, const T: usize>(
    uint: &UInt<LIMBS>,
    by: &[u64; T],
    r: &UInt<LIMBS>,
    modulus: &UInt<LIMBS>,
    inv: Limb,
) -> UInt<LIMBS> {
    let mut res = *r;
    let mut i = T - 1;
    loop {
        let mut j = 63;
        loop {
            res = uint_square_mod(&res, modulus, inv);
            if ((by[i] >> j) & 1) == 1 {
                res = uint_mul_mod(&res, &uint, modulus, inv);
            }
            if j == 0 {
                break;
            }
            j -= 1;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    res
}

/// Implements Algorithm 2 from Patrick Longa's
/// [ePrint 2022-367](https://eprint.iacr.org/2022/367) §3.
#[inline(always)]
pub const fn uint_sum_of_products_mod<const LIMBS: usize, const T: usize>(
    a: &[UInt<LIMBS>; T],
    b: &[UInt<LIMBS>; T],
    modulus: &UInt<LIMBS>,
    inv: Limb,
) -> UInt<LIMBS> {
    // For a single `a x b` multiplication, operand scanning (schoolbook) takes each
    // limb of `a` in turn, and multiplies it by all of the limbs of `b` to compute
    // the result as a double-width intermediate representation, which is then fully
    // reduced at the end. Here however we have pairs of multiplications (a_i, b_i),
    // the results of which are summed.
    //
    // The intuition for this algorithm is two-fold:
    // - We can interleave the operand scanning for each pair, by processing the jth
    //   limb of each `a_i` together. As these have the same offset within the overall
    //   operand scanning flow, their results can be summed directly.
    // - We can interleave the multiplication and reduction steps, resulting in a
    //   single bitshift by the limb size after each iteration. This means we only
    //   need to store a single extra limb overall, instead of keeping around all the
    //   intermediate results and eventually having twice as many limbs.

    let mod_words = modulus.limbs();
    let mut limbs = [Limb::ZERO; LIMBS];
    let mut j = 0;

    while j < LIMBS {
        let mut i1 = 0;
        let mut carry = Limb::ZERO;

        while i1 < T {
            let aj = a[i1].limbs()[j];
            let bl = b[i1].limbs();
            let mut carry2 = Limb::ZERO;
            let mut k = 0;
            while k < LIMBS {
                let (l, c) = limbs[k].mac(aj, bl[k], carry2);
                limbs[k] = l;
                carry2 = c;
                k += 1;
            }
            let (l, _) = carry.adc(Limb::ZERO, carry2);
            carry = l;
            i1 += 1;
        }

        // Algorithm 2, lines 4-5
        // This is a single step of the usual Montgomery reduction process.
        let k = limbs[0].wrapping_mul(inv);
        let (_, c) = limbs[0].mac(k, mod_words[0], Limb::ZERO);
        let mut carry2 = c;
        let mut i2 = 1;
        while i2 < LIMBS {
            let (l, c) = limbs[i2].mac(k, mod_words[i2], carry2);
            limbs[i2 - 1] = l;
            carry2 = c;
            i2 += 1;
        }
        let (l, _) = carry.adc(Limb::ZERO, carry2);
        limbs[i2 - 1] = l;
        j += 1;
    }

    // Final conditional subtraction to ensure the output is in range.
    uint_try_sub(&UInt::new(limbs), modulus)
}

#[inline(always)]
pub const fn uint_try_sub<const LIMBS: usize>(
    uint: &UInt<LIMBS>,
    modulus: &UInt<LIMBS>,
) -> UInt<LIMBS> {
    let (sub, borrow) = uint.sbb(&modulus, Limb::ZERO);
    let mut i = 0;
    let mut res = sub.to_words();
    let prev = uint.as_words();

    while i < LIMBS {
        // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
        // borrow = 0x000...000. Thus, we use it as a mask!
        res[i] = (prev[i] & borrow.0) | (res[i] & !borrow.0);
        i += 1;
    }

    UInt::from_words(res)
}

macro_rules! impl_add_binop_specify_output {
    ($lhs:ident, $rhs:ident, $output:ident) => {
        impl<'b> Add<&'b $rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn add(self, rhs: &'b $rhs) -> $output {
                &self + rhs
            }
        }

        impl<'a> Add<$rhs> for &'a $lhs {
            type Output = $output;

            #[inline]
            fn add(self, rhs: $rhs) -> $output {
                self + &rhs
            }
        }

        impl Add<$rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn add(self, rhs: $rhs) -> $output {
                &self + &rhs
            }
        }
    };
}

macro_rules! impl_sub_binop_specify_output {
    ($lhs:ident, $rhs:ident, $output:ident) => {
        impl<'b> Sub<&'b $rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn sub(self, rhs: &'b $rhs) -> $output {
                &self - rhs
            }
        }

        impl<'a> Sub<$rhs> for &'a $lhs {
            type Output = $output;

            #[inline]
            fn sub(self, rhs: $rhs) -> $output {
                self - &rhs
            }
        }

        impl Sub<$rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn sub(self, rhs: $rhs) -> $output {
                &self - &rhs
            }
        }
    };
}

macro_rules! impl_binops_additive_specify_output {
    ($lhs:ident, $rhs:ident, $output:ident) => {
        impl_add_binop_specify_output!($lhs, $rhs, $output);
        impl_sub_binop_specify_output!($lhs, $rhs, $output);
    };
}

macro_rules! impl_binops_multiplicative_mixed {
    ($lhs:ident, $rhs:ident, $output:ident) => {
        impl<'b> Mul<&'b $rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn mul(self, rhs: &'b $rhs) -> $output {
                &self * rhs
            }
        }

        impl<'a> Mul<$rhs> for &'a $lhs {
            type Output = $output;

            #[inline]
            fn mul(self, rhs: $rhs) -> $output {
                self * &rhs
            }
        }

        impl Mul<$rhs> for $lhs {
            type Output = $output;

            #[inline]
            fn mul(self, rhs: $rhs) -> $output {
                &self * &rhs
            }
        }
    };
}

macro_rules! impl_binops_additive {
    ($lhs:ident, $rhs:ident) => {
        impl_binops_additive_specify_output!($lhs, $rhs, $lhs);

        impl SubAssign<$rhs> for $lhs {
            #[inline]
            fn sub_assign(&mut self, rhs: $rhs) {
                *self = &*self - &rhs;
            }
        }

        impl AddAssign<$rhs> for $lhs {
            #[inline]
            fn add_assign(&mut self, rhs: $rhs) {
                *self = &*self + &rhs;
            }
        }

        impl<'b> SubAssign<&'b $rhs> for $lhs {
            #[inline]
            fn sub_assign(&mut self, rhs: &'b $rhs) {
                *self = &*self - rhs;
            }
        }

        impl<'b> AddAssign<&'b $rhs> for $lhs {
            #[inline]
            fn add_assign(&mut self, rhs: &'b $rhs) {
                *self = &*self + rhs;
            }
        }
    };
}

macro_rules! impl_binops_multiplicative {
    ($lhs:ident, $rhs:ident) => {
        impl_binops_multiplicative_mixed!($lhs, $rhs, $lhs);

        impl MulAssign<$rhs> for $lhs {
            #[inline]
            fn mul_assign(&mut self, rhs: $rhs) {
                *self = &*self * &rhs;
            }
        }

        impl<'b> MulAssign<&'b $rhs> for $lhs {
            #[inline]
            fn mul_assign(&mut self, rhs: &'b $rhs) {
                *self = &*self * rhs;
            }
        }
    };
}
