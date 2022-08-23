use crypto_bigint::{Limb, UInt};
use subtle::{Choice, ConditionallySelectable, CtOption};

/// A helper implementing operations on elements in Mongomery form.
pub struct Montgomery<const LIMBS: usize> {
    pub modulus: UInt<LIMBS>,
    /// INV = -(q^{-1} mod 2^(Limb::BYTE_SIZE)) mod 2^(Limb::BYTE_SIZE)
    pub inv: Limb,
    /// R = 2^(UInt::BIT_SIZE) mod q
    pub r: UInt<LIMBS>,
    /// R2 = 2^(UInt::BIT_SIZE * 2) mod q
    pub r2: UInt<LIMBS>,
    /// R3 = 2^(UInt::BIT_SIZE * 3) mod q
    pub r3: UInt<LIMBS>,
}

impl<const LIMBS: usize> Montgomery<LIMBS> {
    pub const fn new(modulus: UInt<LIMBS>) -> Self {
        let inv = uint_reduction_inv(&modulus);
        let bits: usize = LIMBS * Limb::BIT_SIZE;
        let r = uint_pow2k_mod(UInt::ONE, bits, &modulus);
        let r2 = uint_pow2k_mod(r, bits, &modulus);
        let r3 = uint_pow2k_mod(r2, bits, &modulus);
        Self {
            modulus,
            inv,
            r,
            r2,
            r3,
        }
    }

    #[inline(always)]
    pub const fn one(&self) -> UInt<LIMBS> {
        self.r
    }

    #[inline(always)]
    pub const fn to_canonical(&self, uint: &UInt<LIMBS>) -> UInt<LIMBS> {
        self.reduce(uint)
    }

    #[inline(always)]
    pub const fn from_canonical(&self, uint: &UInt<LIMBS>) -> UInt<LIMBS> {
        uint_mul_mod(uint, &self.r2, &self.modulus, self.inv)
    }

    #[inline(always)]
    // The lower bits are multiplied by `R^2`, as normal.
    // The upper bits are multiplied by `R^2 * 2^256 = R^3`.
    pub const fn from_canonical_wide(&self, lo: UInt<LIMBS>, hi: UInt<LIMBS>) -> UInt<LIMBS> {
        self.sum_of_products(&[lo, hi], &[self.r2, self.r3])
    }

    #[inline(always)]
    pub fn try_from_canonical(&self, uint: &UInt<LIMBS>) -> CtOption<UInt<LIMBS>> {
        // Is the value smaller than the modulus?
        // (NB: checked_sub could be used here, but is currently slower due to not being inlined)
        let (_, borrow) = uint.sbb(&self.modulus, Limb::ZERO);
        let is_some = Choice::from((borrow.0 as u8) & 1);

        // Convert to Montgomery form by computing
        // (a.R^0 * R^2) / R = a.R
        let res = self.from_canonical(uint);

        CtOption::new(res, is_some)
    }

    #[inline(always)]
    pub const fn reduce(&self, uint: &UInt<LIMBS>) -> UInt<LIMBS> {
        uint_montgomery_reduce(*uint, UInt::ZERO, &self.modulus, self.inv)
    }

    #[inline(always)]
    pub const fn add(&self, lhs: &UInt<LIMBS>, rhs: &UInt<LIMBS>) -> UInt<LIMBS> {
        // Because self + rhs never carries (we assume that both are < q),
        // this is more efficient than U256::add_mod.
        let (sum, _) = lhs.adc(&rhs, Limb::ZERO);
        uint_try_sub(&sum, &self.modulus)
    }

    #[inline(always)]
    pub const fn double(&self, uint: &UInt<LIMBS>) -> UInt<LIMBS> {
        let sum = uint.shl_vartime(1);
        uint_try_sub(&sum, &self.modulus)
    }

    #[inline(always)]
    pub const fn sub(&self, lhs: &UInt<LIMBS>, rhs: &UInt<LIMBS>) -> UInt<LIMBS> {
        lhs.sub_mod(&rhs, &self.modulus)
    }

    #[inline(always)]
    pub const fn neg(&self, uint: &UInt<LIMBS>) -> UInt<LIMBS> {
        uint.neg_mod(&self.modulus)
    }

    #[inline(always)]
    pub const fn mul(&self, lhs: &UInt<LIMBS>, rhs: &UInt<LIMBS>) -> UInt<LIMBS> {
        uint_mul_mod(&lhs, &rhs, &self.modulus, self.inv)
    }

    #[inline(always)]
    pub const fn square(&self, uint: &UInt<LIMBS>) -> UInt<LIMBS> {
        uint_square_mod(&uint, &self.modulus, self.inv)
    }

    #[inline(always)]
    pub fn pow<const T: usize>(&self, lhs: &UInt<LIMBS>, rhs: &UInt<T>) -> UInt<LIMBS> {
        uint_pow_mod(&lhs, &rhs, &self.r, &self.modulus, self.inv)
    }

    #[inline(always)]
    pub const fn pow_vartime<const T: usize>(
        &self,
        lhs: &UInt<LIMBS>,
        rhs: &UInt<T>,
    ) -> UInt<LIMBS> {
        uint_pow_vartime_mod(&lhs, &rhs, &self.r, &self.modulus, self.inv)
    }

    #[inline(always)]
    pub const fn sum_of_products<const T: usize>(
        &self,
        a: &[UInt<LIMBS>; T],
        b: &[UInt<LIMBS>; T],
    ) -> UInt<LIMBS> {
        uint_sum_of_products_mod(a, b, &self.modulus, self.inv)
    }
}

/// Calculate `(uint * 2^exp) mod q`. Only used for `R`, `R2`, `R3` calculation.
/// NB: Assumes that `uint < modulus` and `modulus.bits() < UInt::BIT_LENGTH`.
const fn uint_pow2k_mod<const LIMBS: usize>(
    mut uint: UInt<LIMBS>,
    exp: usize,
    modulus: &UInt<LIMBS>,
) -> UInt<LIMBS> {
    let mut i = 0;
    while i < exp {
        uint = uint_try_sub(&uint.shl_vartime(1), &modulus);
        i += 1;
    }
    uint
}

/// Calculate `-(q^{-1} mod 2^(Limb::BYTE_SIZE)) mod 2^(Limb::BYTE_SIZE)`
/// for use in montgomery reduction.
const fn uint_reduction_inv<const LIMBS: usize>(modulus: &UInt<LIMBS>) -> Limb {
    modulus
        .inv_mod2k(Limb::BIT_SIZE)
        .neg_mod(&UInt::ONE.shl_vartime(Limb::BIT_SIZE))
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
    let mod_limbs = modulus.limbs();
    let hi_words = hi.limbs();
    let mut limbs = lo.into_limbs();
    let mut carry = Limb::ZERO;
    let mut i = 0;

    while i < LIMBS {
        let k = limbs[0].wrapping_mul(inv);
        let mut carry2 = Limb::ZERO;
        let mut j = 0;

        while j < LIMBS {
            let (l, c) = limbs[j].mac(k, mod_limbs[j], carry2);
            if j != 0 {
                limbs[j - 1] = l;
            }
            carry2 = c;
            j += 1;
        }

        let (l, c) = hi_words[i].adc(carry, carry2);
        limbs[LIMBS - 1] = l;
        carry = c;
        i += 1;
    }

    // Final conditional subtraction to ensure the output is in range.
    uint_try_sub(&UInt::new(limbs), modulus)
}

/// Multiplies two elements mod q.
#[inline(always)]
pub const fn uint_mul_mod<const LIMBS: usize>(
    lhs: &UInt<LIMBS>,
    rhs: &UInt<LIMBS>,
    modulus: &UInt<LIMBS>,
    inv: Limb,
) -> UInt<LIMBS> {
    uint_sum_of_products_mod(&[*lhs], &[*rhs], modulus, inv)
}

/// Squares an element mod q.
#[inline(always)]
pub const fn uint_square_mod<const LIMBS: usize>(
    uint: &UInt<LIMBS>,
    modulus: &UInt<LIMBS>,
    inv: Limb,
) -> UInt<LIMBS> {
    let uint = [*uint];
    uint_sum_of_products_mod(&uint, &uint, modulus, inv)
}

/// Calculates `uint^by mod q` in constant time.
///
/// Based on Algorithm 14.94 in Handbook of Applied Cryptography
/// <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.
#[inline(always)]
pub fn uint_pow_mod<const LIMBS: usize, const T: usize>(
    uint: &UInt<LIMBS>,
    by: &UInt<T>,
    r: &UInt<LIMBS>,
    modulus: &UInt<LIMBS>,
    inv: Limb,
) -> UInt<LIMBS> {
    let mut res = *r;
    let mut i = T - 1;
    loop {
        let wd = by.as_words()[i];
        let mut j = Limb::BIT_SIZE - 1;
        let mut square = true;
        loop {
            let rhs;
            if square {
                rhs = res;
            } else {
                let add = Choice::from(((wd >> j) & 1) as u8);
                rhs = UInt::conditional_select(&r, &uint, add);
            }
            res = uint_mul_mod(&res, &rhs, modulus, inv);
            if !square {
                if j == 0 {
                    break;
                }
                j -= 1;
            }
            square = !square;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    res
}

/// Although this is labeled "vartime", it is only variable time with
/// respect to the exponent.
/// Based on Algorithm 14.94 in Handbook of Applied Cryptography
/// <http://cacr.uwaterloo.ca/hac/about/chap14.pdf>.
#[inline(always)]
pub const fn uint_pow_vartime_mod<const LIMBS: usize, const T: usize>(
    uint: &UInt<LIMBS>,
    by: &UInt<T>,
    r: &UInt<LIMBS>,
    modulus: &UInt<LIMBS>,
    inv: Limb,
) -> UInt<LIMBS> {
    let mut res = *r;
    let mut i = T - 1;
    loop {
        let wd = by.as_words()[i];
        let mut j = Limb::BIT_SIZE - 1;
        let mut square = true;
        loop {
            let rhs;
            let skip;
            if square {
                rhs = &res;
                skip = false;
            } else {
                rhs = &uint;
                skip = (wd >> j) & 1 == 0;
            }
            if !skip {
                res = uint_mul_mod(&res, rhs, modulus, inv);
            }
            if !square {
                if j == 0 {
                    break;
                }
                j -= 1;
            }
            square = !square;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    res
}

/// Returns `c = a.zip(b).fold(0, |acc, (a_i, b_i)| acc + a_i * b_i)`.
///
/// Implements Algorithm 2 from Patrick Longa's
/// [ePrint 2022-367](https://eprint.iacr.org/2022/367) §3.
/// Elements of a and b are not required to be < q.
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

    let mod_limbs = modulus.limbs();
    let mut limbs = [Limb::ZERO; LIMBS];
    let mut i = 0;

    while i < LIMBS {
        let mut carry = Limb::ZERO;
        let mut j1 = 0;

        while j1 < T {
            let al = a[j1].limbs();
            let bl = b[j1].limbs();
            let mut carry2 = Limb::ZERO;
            let mut k = 0;
            while k < LIMBS {
                let (l, c) = limbs[k].mac(al[i], bl[k], carry2);
                limbs[k] = l;
                carry2 = c;
                k += 1;
            }
            let (l, _) = Limb::ZERO.adc(carry, carry2);
            carry = l;
            j1 += 1;
        }

        // Algorithm 2, lines 4-5
        // This is a single step of the usual Montgomery reduction process.
        let k = limbs[0].wrapping_mul(inv);
        let mut carry2 = Limb::ZERO;
        let mut j2 = 0;
        while j2 < LIMBS {
            let (l, c) = limbs[j2].mac(k, mod_limbs[j2], carry2);
            if j2 != 0 {
                limbs[j2 - 1] = l;
            }
            carry2 = c;
            j2 += 1;
        }
        let (l, _) = Limb::ZERO.adc(carry, carry2);
        limbs[LIMBS - 1] = l;
        i += 1;
    }

    // Final conditional subtraction to ensure the output is in range.
    uint_try_sub(&UInt::new(limbs), modulus)
}

/// Try to subtract `rhs` from `lhs` in constant time, returning the original `lhs`
/// if the subtraction would underflow.
#[inline(always)]
pub const fn uint_try_sub<const LIMBS: usize>(lhs: &UInt<LIMBS>, rhs: &UInt<LIMBS>) -> UInt<LIMBS> {
    let (sub, borrow) = lhs.sbb(&rhs, Limb::ZERO);
    let mut res = sub.to_words();
    let prev = lhs.as_words();
    let mut i = 0;

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
