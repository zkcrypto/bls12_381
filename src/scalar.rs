//! This module provides an implementation of the BLS12-381 scalar field $\mathbb{F}_q$
//! where `q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use rand_core::RngCore;

use crypto_bigint::{Encoding, Limb, U256};
use ff::{Field, PrimeField};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "bits")]
use ff::{FieldBits, PrimeFieldBits};

use crate::util::{
    uint_montgomery_reduce, uint_mul_mod, uint_pow_vartime, uint_reduction_inv, uint_square_mod,
    uint_try_sub,
};

/// Represents an element of the scalar field $\mathbb{F}_q$ of the BLS12-381 elliptic
/// curve construction.
// The internal representation of this type is four 64-bit unsigned
// integers in little-endian order. `Scalar` values are always in
// Montgomery form; i.e., Scalar(a) = aR mod q, with R = 2^256.
#[derive(Clone, Copy, Eq)]
#[repr(transparent)]
pub struct Scalar(pub(crate) U256);

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tmp = self.to_bytes();
        write!(f, "0x")?;
        for &b in tmp.iter().rev() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<u64> for Scalar {
    fn from(val: u64) -> Scalar {
        Scalar::from_canonical(U256::from_u64(val))
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Scalar {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar(U256::conditional_select(&a.0, &b.0, choice))
    }
}

/// Constant representing the modulus (q)
const MODULUS: U256 = U256::from_be_hex(
    "73eda753299d7d48\
     3339d80809a1d805\
     53bda402fffe5bfe\
     ffffffff00000001",
);

// The number of bits needed to represent the modulus.
const MODULUS_BITS: u32 = 255;

// GENERATOR = 7 (multiplicative generator of r-1 order, that is also quadratic nonresidue)
const GENERATOR: Scalar = Scalar::reduced([
    0x0000_000e_ffff_fff1,
    0x17e3_63d3_0018_9c0f,
    0xff9c_5787_6f84_57b0,
    0x3513_3220_8fc5_a8c4,
]);

impl<'a> Neg for &'a Scalar {
    type Output = Scalar;

    #[inline]
    fn neg(self) -> Scalar {
        self.neg()
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    #[inline]
    fn neg(self) -> Scalar {
        -&self
    }
}

impl<'a, 'b> Sub<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    #[inline]
    fn sub(self, rhs: &'b Scalar) -> Scalar {
        self.sub(rhs)
    }
}

impl<'a, 'b> Add<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    #[inline]
    fn add(self, rhs: &'b Scalar) -> Scalar {
        self.add(rhs)
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    #[inline]
    fn mul(self, rhs: &'b Scalar) -> Scalar {
        self.mul(rhs)
    }
}

impl_binops_additive!(Scalar, Scalar);
impl_binops_multiplicative!(Scalar, Scalar);

/// INV = -(q^{-1} mod 2^64) mod 2^64
const INV: Limb = uint_reduction_inv(&MODULUS);

/// R = 2^256 mod q
const R: U256 = U256::from_be_hex(
    "1824b159acc5056f\
     998c4fefecbc4ff5\
     5884b7fa00034802\
     00000001fffffffe",
);

/// R^2 = 2^512 mod q
const R2: U256 = U256::from_be_hex(
    "0748d9d99f59ff11\
     05d314967254398f\
     2b6cedcb87925c23\
     c999e990f3f29c6d",
);

/// R^3 = 2^768 mod q
const R3: U256 = U256::from_be_hex(
    "6e2a5bb9c8db33e9\
     73d13c71c7b5f418\
     1b3e0d188cf06990\
     c62c1807439b73af",
);

// 2^S * t = MODULUS - 1 with t odd
const S: u32 = 32;

/// GENERATOR^t where t * 2^s + 1 = q
/// with t odd. In other words, this
/// is a 2^s root of unity.
///
/// `GENERATOR = 7 mod q` is a generator
/// of the q - 1 order multiplicative
/// subgroup.
const ROOT_OF_UNITY: Scalar = Scalar::reduced([
    0xb9b5_8d8c_5f0e_466a,
    0x5b1b_4c80_1819_d7ec,
    0x0af5_3ae3_52a3_1e64,
    0x5bf3_adda_19e9_b27b,
]);

impl Default for Scalar {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for Scalar {}

impl Scalar {
    /// Returns zero, the additive identity.
    #[inline]
    pub const fn zero() -> Scalar {
        Scalar(U256::ZERO)
    }

    /// Returns one, the multiplicative identity.
    #[inline]
    pub const fn one() -> Scalar {
        Scalar(R)
    }

    /// Doubles this field element.
    #[inline]
    pub const fn double(&self) -> Scalar {
        let sum = self.0.shl_vartime(1);
        Scalar(uint_try_sub(&sum, &MODULUS))
    }

    /// Attempts to convert a little-endian byte representation of
    /// a scalar into a `Scalar`, failing if the input is not canonical.
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Scalar> {
        let tmp = U256::from_le_bytes(*bytes);

        // Is the value smaller than the modulus?
        let (_, borrow) = tmp.sbb(&MODULUS, Limb::ZERO);
        let is_some = Choice::from((borrow.0 as u8) & 1);

        // Convert to Montgomery form by computing
        // (a.R^0 * R^2) / R = a.R
        let res = Self::from_canonical(tmp);

        CtOption::new(res, is_some)
    }

    /// Converts an element of `Scalar` into a byte representation in
    /// little-endian byte order.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.to_canonical().to_le_bytes()
    }

    /// Converts a 512-bit little endian integer into
    /// a `Scalar` by reducing by the modulus.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar {
        // We reduce an arbitrary 512-bit number by decomposing it into two 256-bit digits
        // with the higher bits multiplied by 2^256. Thus, we perform two reductions
        //
        // 1. the lower bits are multiplied by R^2, as normal
        // 2. the upper bits are multiplied by R^2 * 2^256 = R^3
        //
        // and computing their sum in the field. It remains to see that arbitrary 256-bit
        // numbers can be placed into Montgomery form safely using the reduction. The
        // reduction works so long as the product is less than R=2^256 multiplied by
        // the modulus. This holds because for any `c` smaller than the modulus, we have
        // that (2^256 - 1)*c is an acceptable product for the reduction. Therefore, the
        // reduction always works so long as `c` is in the field; in this case it is either the
        // constant `R2` or `R3`.
        let d0 = U256::from_le_bytes(bytes[0..32].try_into().unwrap());
        let d1 = U256::from_le_bytes(bytes[32..64].try_into().unwrap());
        let (l0, h0) = d0.mul_wide(&R2);
        let (l1, h1) = d1.mul_wide(&R3);
        let (lo, carry) = l0.adc(&l1, Limb::ZERO);
        // will not carry because R2 and R3 are both mod q
        let (hi, _) = h0.adc(&h1, carry);
        Scalar(uint_montgomery_reduce(lo, hi, &MODULUS, INV))
    }

    /// Converts from a canonical scalar represented by a U256.
    #[inline]
    pub(crate) const fn from_canonical(val: U256) -> Self {
        Scalar(uint_mul_mod(&val, &R2, &MODULUS, INV))
    }

    /// Turn into canonical form by computing
    /// (a.R) / R = a
    #[inline]
    pub(crate) const fn to_canonical(&self) -> U256 {
        uint_montgomery_reduce(self.0, U256::ZERO, &MODULUS, INV)
    }

    /// Converts from an integer represented in little endian
    /// into its (congruent) `Scalar` representation.
    pub const fn from_raw(val: [u64; 4]) -> Self {
        Scalar::from_canonical(uint_from_raw(val))
    }

    #[inline]
    #[allow(unused)]
    pub(crate) const fn to_raw(&self) -> [u64; 4] {
        uint_to_raw(self.0)
    }

    #[inline]
    pub(crate) const fn reduced(val: [u64; 4]) -> Self {
        Scalar(uint_from_raw(val))
    }

    /// Squares this element.
    #[inline]
    pub const fn square(&self) -> Scalar {
        Scalar(uint_square_mod(&self.0, &MODULUS, INV))
    }

    /// Computes the square root of this element, if it exists.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Tonelli-Shank's algorithm for q mod 16 = 1
        // https://eprint.iacr.org/2012/685.pdf (page 12, algorithm 5)

        // w = self^((t - 1) // 2)
        //   = self^6104339283789297388802252303364915521546564123189034618274734669823
        let w = self.pow_vartime(&[
            0x7fff_2dff_7fff_ffff,
            0x04d0_ec02_a9de_d201,
            0x94ce_bea4_199c_ec04,
            0x0000_0000_39f6_d3a9,
        ]);

        let mut v = S;
        let mut x = self * w;
        let mut b = x * w;

        // Initialize z as the 2^S root of unity.
        let mut z = ROOT_OF_UNITY;

        for max_v in (1..=S).rev() {
            let mut k = 1;
            let mut tmp = b.square();
            let mut j_less_than_v: Choice = 1.into();

            for j in 2..max_v {
                let tmp_is_one = tmp.ct_eq(&Scalar::one());
                let squared = Scalar::conditional_select(&tmp, &z, tmp_is_one).square();
                tmp = Scalar::conditional_select(&squared, &tmp, tmp_is_one);
                let new_z = Scalar::conditional_select(&z, &squared, tmp_is_one);
                j_less_than_v &= !j.ct_eq(&v);
                k = u32::conditional_select(&j, &k, tmp_is_one);
                z = Scalar::conditional_select(&z, &new_z, j_less_than_v);
            }

            let result = x * z;
            x = Scalar::conditional_select(&result, &x, b.ct_eq(&Scalar::one()));
            z = z.square();
            b *= z;
            v = k;
        }

        CtOption::new(
            x,
            (x * x).ct_eq(self), // Only return Some if it's the square root.
        )
    }

    /// Exponentiates `self` by `by`, where `by` is a
    /// little-endian order integer exponent.
    pub fn pow(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();
                let mut tmp = res;
                tmp *= self;
                res.conditional_assign(&tmp, (((*e >> i) & 0x1) as u8).into());
            }
        }
        res
    }

    /// Exponentiates `self` by `by`, where `by` is a
    /// little-endian order integer exponent.
    ///
    /// **This operation is variable time with respect
    /// to the exponent.** If the exponent is fixed,
    /// this operation is effectively constant time.
    pub const fn pow_vartime(&self, by: &[u64; 4]) -> Self {
        Scalar(uint_pow_vartime(&self.0, by, &R, &MODULUS, INV))
    }

    /// Computes the multiplicative inverse of this element,
    /// failing if the element is zero.
    pub fn invert(&self) -> CtOption<Self> {
        #[inline(always)]
        fn square_assign_multi(n: &mut Scalar, num_times: usize) {
            for _ in 0..num_times {
                *n = n.square();
            }
        }
        // found using https://github.com/kwantam/addchain
        let mut t0 = self.square();
        let mut t1 = t0 * self;
        let mut t16 = t0.square();
        let mut t6 = t16.square();
        let mut t5 = t6 * t0;
        t0 = t6 * t16;
        let mut t12 = t5 * t16;
        let mut t2 = t6.square();
        let mut t7 = t5 * t6;
        let mut t15 = t0 * t5;
        let mut t17 = t12.square();
        t1 *= t17;
        let mut t3 = t7 * t2;
        let t8 = t1 * t17;
        let t4 = t8 * t2;
        let t9 = t8 * t7;
        t7 = t4 * t5;
        let t11 = t4 * t17;
        t5 = t9 * t17;
        let t14 = t7 * t15;
        let t13 = t11 * t12;
        t12 = t11 * t17;
        t15 *= &t12;
        t16 *= &t15;
        t3 *= &t16;
        t17 *= &t3;
        t0 *= &t17;
        t6 *= &t0;
        t2 *= &t6;
        square_assign_multi(&mut t0, 8);
        t0 *= &t17;
        square_assign_multi(&mut t0, 9);
        t0 *= &t16;
        square_assign_multi(&mut t0, 9);
        t0 *= &t15;
        square_assign_multi(&mut t0, 9);
        t0 *= &t15;
        square_assign_multi(&mut t0, 7);
        t0 *= &t14;
        square_assign_multi(&mut t0, 7);
        t0 *= &t13;
        square_assign_multi(&mut t0, 10);
        t0 *= &t12;
        square_assign_multi(&mut t0, 9);
        t0 *= &t11;
        square_assign_multi(&mut t0, 8);
        t0 *= &t8;
        square_assign_multi(&mut t0, 8);
        t0 *= self;
        square_assign_multi(&mut t0, 14);
        t0 *= &t9;
        square_assign_multi(&mut t0, 10);
        t0 *= &t8;
        square_assign_multi(&mut t0, 15);
        t0 *= &t7;
        square_assign_multi(&mut t0, 10);
        t0 *= &t6;
        square_assign_multi(&mut t0, 8);
        t0 *= &t5;
        square_assign_multi(&mut t0, 16);
        t0 *= &t3;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 7);
        t0 *= &t4;
        square_assign_multi(&mut t0, 9);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t3;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t3;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 5);
        t0 *= &t1;
        square_assign_multi(&mut t0, 5);
        t0 *= &t1;

        CtOption::new(t0, !self.ct_eq(&Self::zero()))
    }

    /// Multiplies `rhs` by `self`, returning the result.
    #[inline]
    pub const fn mul(&self, rhs: &Self) -> Self {
        Scalar(uint_mul_mod(&self.0, &rhs.0, &MODULUS, INV))
    }

    /// Subtracts `rhs` from `self`, returning the result.
    #[inline]
    pub const fn sub(&self, rhs: &Self) -> Self {
        Scalar(self.0.sub_mod(&rhs.0, &MODULUS))
    }

    /// Adds `rhs` to `self`, returning the result.
    #[inline]
    pub const fn add(&self, rhs: &Self) -> Self {
        // Because self + rhs never carries (we assume that both are < q),
        // this is more efficient than U256::add_mod.
        let (sum, _) = self.0.adc(&rhs.0, Limb::ZERO);
        Scalar(uint_try_sub(&sum, &MODULUS))
    }

    /// Negates `self`.
    #[inline]
    pub const fn neg(&self) -> Self {
        Scalar(self.0.neg_mod(&MODULUS))
    }
}

impl From<U256> for Scalar {
    fn from(value: U256) -> Scalar {
        Scalar::from_canonical(value)
    }
}

impl From<&U256> for Scalar {
    fn from(value: &U256) -> Scalar {
        Scalar::from_canonical(*value)
    }
}

impl From<Scalar> for [u8; 32] {
    fn from(value: Scalar) -> [u8; 32] {
        value.to_bytes()
    }
}

impl<'a> From<&Scalar> for [u8; 32] {
    fn from(value: &Scalar) -> [u8; 32] {
        value.to_bytes()
    }
}

impl Field for Scalar {
    fn random(mut rng: impl RngCore) -> Self {
        let mut buf = [0; 64];
        rng.fill_bytes(&mut buf);
        Self::from_bytes_wide(&buf)
    }

    fn zero() -> Self {
        Self::zero()
    }

    fn one() -> Self {
        Self::one()
    }

    #[must_use]
    fn square(&self) -> Self {
        self.square()
    }

    #[must_use]
    fn double(&self) -> Self {
        self.double()
    }

    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }

    fn sqrt(&self) -> CtOption<Self> {
        self.sqrt()
    }
}

impl PrimeField for Scalar {
    type Repr = [u8; 32];

    fn from_repr(r: Self::Repr) -> CtOption<Self> {
        Self::from_bytes(&r)
    }

    fn to_repr(&self) -> Self::Repr {
        self.to_bytes()
    }

    fn is_odd(&self) -> Choice {
        Choice::from(self.to_bytes()[0] & 1)
    }

    const NUM_BITS: u32 = MODULUS_BITS;
    const CAPACITY: u32 = Self::NUM_BITS - 1;

    fn multiplicative_generator() -> Self {
        GENERATOR
    }

    const S: u32 = S;

    fn root_of_unity() -> Self {
        ROOT_OF_UNITY
    }
}

#[cfg(all(feature = "bits", target_pointer_width = "32"))]
type ReprBits = [u32; 8];

#[cfg(all(feature = "bits", target_pointer_width = "64"))]
type ReprBits = [u64; 4];

#[cfg(feature = "bits")]
impl PrimeFieldBits for Scalar {
    type ReprBits = ReprBits;

    fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
        FieldBits::new(self.to_canonical().to_words())
    }

    fn char_le_bits() -> FieldBits<Self::ReprBits> {
        FieldBits::new(MODULUS.to_words())
    }
}

impl<T> core::iter::Sum<T> for Scalar
where
    T: core::borrow::Borrow<Scalar>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::zero(), |acc, item| acc + item.borrow())
    }
}

#[inline]
#[cfg(target_pointer_width = "32")]
const fn uint_from_raw(arr: [u64; 4]) -> U256 {
    const MASK: u64 = u32::MAX as u64;
    U256::from_words([
        (arr[0] & MASK) as u32,
        (arr[0] >> 32) as u32,
        (arr[1] & MASK) as u32,
        (arr[1] >> 32) as u32,
        (arr[2] & MASK) as u32,
        (arr[2] >> 32) as u32,
        (arr[3] & MASK) as u32,
        (arr[3] >> 32) as u32,
    ])
}

#[inline]
#[cfg(target_pointer_width = "64")]
const fn uint_from_raw(arr: [u64; 4]) -> U256 {
    U256::from_words(arr)
}

#[inline]
#[cfg(target_pointer_width = "32")]
const fn uint_to_raw(uint: U256) -> [u64; 4] {
    let words = uint.as_words();
    [
        (words[0] as u64) | ((words[1] as u64) << 32),
        (words[2] as u64) | ((words[3] as u64) << 32),
        (words[4] as u64) | ((words[5] as u64) << 32),
        (words[6] as u64) | ((words[7] as u64) << 32),
    ]
}

#[inline]
#[cfg(target_pointer_width = "64")]
const fn uint_to_raw(uint: U256) -> [u64; 4] {
    uint.to_words()
}

#[cfg(target_pointer_width = "32")]
#[test]
fn test_inv() {
    // Compute -(q^{-1} mod 2^32) mod 2^32 by exponentiating
    // by totient(2**32) - 1

    let mut inv = 1u32;
    for _ in 0..31 {
        inv = inv.wrapping_mul(inv);
        inv = inv.wrapping_mul(MODULUS.as_words()[0]);
    }
    inv = inv.wrapping_neg();

    assert_eq!(Limb(inv), INV);
}

#[cfg(target_pointer_width = "64")]
#[test]
fn test_inv() {
    // Compute -(q^{-1} mod 2^64) mod 2^64 by exponentiating
    // by totient(2**64) - 1

    let mut inv = 1u64;
    for _ in 0..63 {
        inv = inv.wrapping_mul(inv);
        inv = inv.wrapping_mul(MODULUS.as_words()[0]);
    }
    inv = inv.wrapping_neg();

    assert_eq!(Limb(inv), INV);
}

#[test]
fn test_debug() {
    assert_eq!(
        format!("{:?}", Scalar::zero()),
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        format!("{:?}", Scalar::one()),
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(
        format!("{:?}", Scalar(R2)),
        "0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe"
    );
}

#[test]
fn test_equality() {
    assert_eq!(Scalar::zero(), Scalar::zero());
    assert_eq!(Scalar::one(), Scalar::one());
    assert_eq!(R2, R2);

    assert!(Scalar::zero() != Scalar::one());
    assert!(Scalar::one() != Scalar(R2));
}

#[test]
fn test_to_bytes() {
    assert_eq!(Scalar::zero().to_bytes(), [0u8; 32]);

    assert_eq!(
        Scalar::one().to_bytes(),
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]
    );

    assert_eq!(
        Scalar(R2).to_bytes(),
        [
            254, 255, 255, 255, 1, 0, 0, 0, 2, 72, 3, 0, 250, 183, 132, 88, 245, 79, 188, 236, 239,
            79, 140, 153, 111, 5, 197, 172, 89, 177, 36, 24
        ]
    );

    assert_eq!(
        (-&Scalar::one()).to_bytes(),
        [
            0, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ]
    );
}

#[test]
fn test_from_bytes() {
    assert_eq!(Scalar::from_bytes(&[0u8; 32]).unwrap(), Scalar::zero());

    assert_eq!(
        Scalar::from_bytes(&[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ])
        .unwrap(),
        Scalar::one()
    );

    assert_eq!(
        Scalar::from_bytes(&[
            254, 255, 255, 255, 1, 0, 0, 0, 2, 72, 3, 0, 250, 183, 132, 88, 245, 79, 188, 236, 239,
            79, 140, 153, 111, 5, 197, 172, 89, 177, 36, 24
        ])
        .unwrap(),
        Scalar(R2)
    );

    // -1 should work
    assert!(bool::from(
        Scalar::from_bytes(&[
            0, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ])
        .is_some()
    ));

    // modulus is invalid
    assert!(bool::from(
        Scalar::from_bytes(&[
            1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ])
        .is_none()
    ));

    // Anything larger than the modulus is invalid
    assert!(bool::from(
        Scalar::from_bytes(&[
            2, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ])
        .is_none()
    ));
    assert!(bool::from(
        Scalar::from_bytes(&[
            1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 58, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ])
        .is_none()
    ));
    assert!(bool::from(
        Scalar::from_bytes(&[
            1, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 116
        ])
        .is_none()
    ));
}

#[test]
fn test_from_bytes_wide_zero() {
    assert_eq!(Scalar::zero(), Scalar::from_bytes_wide(&[0x00; 64]));
}

#[test]
fn test_from_bytes_wide_r() {
    assert_eq!(
        Scalar(R),
        Scalar::from_bytes_wide(&[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ])
    );
}

#[test]
fn test_from_bytes_wide_r2() {
    assert_eq!(
        Scalar(R2),
        Scalar::from_bytes_wide(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0
        ])
    );
}

#[test]
fn test_from_bytes_wide_negative_one() {
    assert_eq!(
        -&Scalar::one(),
        Scalar::from_bytes_wide(&[
            0, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
    );
}

#[test]
fn test_from_bytes_wide_maximum() {
    assert_eq!(
        Scalar(R3) - Scalar::one(),
        Scalar::from_bytes_wide(&[0xff; 64])
    );
}

#[test]
fn test_zero() {
    assert_eq!(Scalar::zero(), -&Scalar::zero());
    assert_eq!(Scalar::zero(), Scalar::zero() + Scalar::zero());
    assert_eq!(Scalar::zero(), Scalar::zero() - Scalar::zero());
    assert_eq!(Scalar::zero(), Scalar::zero() * Scalar::zero());
}

#[cfg(test)]
const LARGEST: Scalar = Scalar::reduced([
    0xffff_ffff_0000_0000,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
]);

#[test]
fn test_addition() {
    let mut tmp = LARGEST;
    tmp += &LARGEST;

    assert_eq!(
        tmp,
        Scalar::reduced([
            0xffff_fffe_ffff_ffff,
            0x53bd_a402_fffe_5bfe,
            0x3339_d808_09a1_d805,
            0x73ed_a753_299d_7d48,
        ])
    );

    let mut tmp = LARGEST;
    tmp += &Scalar::reduced([1, 0, 0, 0]);

    assert_eq!(tmp, Scalar::zero());
}

#[test]
fn test_negation() {
    let tmp = -&LARGEST;

    assert_eq!(tmp, Scalar::reduced([1, 0, 0, 0]));

    let tmp = -&Scalar::zero();
    assert_eq!(tmp, Scalar::zero());
    let tmp = -&Scalar::reduced([1, 0, 0, 0]);
    assert_eq!(tmp, LARGEST);
}

#[test]
fn test_subtraction() {
    let mut tmp = LARGEST;
    tmp -= &LARGEST;

    assert_eq!(tmp, Scalar::zero());

    let mut tmp = Scalar::zero();
    tmp -= &LARGEST;

    let mut tmp2 = Scalar(MODULUS);
    tmp2 -= &LARGEST;

    assert_eq!(tmp, tmp2);
}

#[test]
fn test_multiplication() {
    let mut cur = LARGEST;

    for _ in 0..100 {
        let mut tmp = cur;
        tmp *= &cur;

        let mut tmp2 = Scalar::zero();
        for b in cur
            .to_bytes()
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1u8) == 1u8))
        {
            let tmp3 = tmp2;
            tmp2 += tmp3;

            if b {
                tmp2 += cur;
            }
        }

        assert_eq!(tmp, tmp2);

        cur += LARGEST;
    }
}

#[test]
fn test_squaring() {
    let mut cur = LARGEST;

    for _ in 0..100 {
        let mut tmp = cur;
        tmp = tmp.square();

        let mut tmp2 = Scalar::zero();
        for b in cur
            .to_bytes()
            .iter()
            .rev()
            .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1u8) == 1u8))
        {
            let tmp3 = tmp2;
            tmp2 += tmp3;

            if b {
                tmp2 += &cur;
            }
        }

        assert_eq!(tmp, tmp2);

        cur += LARGEST;
    }
}

#[test]
fn test_inversion() {
    assert!(bool::from(Scalar::zero().invert().is_none()));
    assert_eq!(Scalar::one().invert().unwrap(), Scalar::one());
    assert_eq!((-&Scalar::one()).invert().unwrap(), -&Scalar::one());

    let mut tmp = Scalar(R2);

    for _ in 0..100 {
        let mut tmp2 = tmp.invert().unwrap();
        tmp2 *= tmp;

        assert_eq!(tmp2, Scalar::one());

        tmp += Scalar(R2);
    }
}

#[test]
fn test_invert_is_pow() {
    let q_minus_2 = [
        0xffff_fffe_ffff_ffff,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ];

    let mut r1 = Scalar::one();
    let mut r2 = Scalar::one();
    let mut r3 = Scalar::one();

    for i in 0..100 {
        r1 = r1.invert().unwrap();
        r2 = r2.pow_vartime(&q_minus_2);
        r3 = r3.pow(&q_minus_2);

        assert_eq!(r1, r2, "failed on {}", i);
        assert_eq!(r2, r3);
        // Add R so we check something different next time around
        r1 += Scalar::one();
        r2 = r1;
        r3 = r1;
    }
}

#[test]
fn test_sqrt() {
    {
        assert_eq!(Scalar::zero().sqrt().unwrap(), Scalar::zero());
    }

    let mut square = Scalar::reduced([
        0x46cd_85a5_f273_077e,
        0x1d30_c47d_d68f_c735,
        0x77f6_56f6_0bec_a0eb,
        0x494a_a01b_df32_468d,
    ]);

    let mut none_count = 0;

    for _ in 0..100 {
        let square_root = square.sqrt();
        if bool::from(square_root.is_none()) {
            none_count += 1;
        } else {
            assert_eq!(square_root.unwrap() * square_root.unwrap(), square);
        }
        square -= Scalar::one();
    }

    assert_eq!(49, none_count);
}

#[test]
fn test_from_raw() {
    assert_eq!(
        Scalar::from_raw([
            0x0001_ffff_fffd,
            0x5884_b7fa_0003_4802,
            0x998c_4fef_ecbc_4ff5,
            0x1824_b159_acc5_056f,
        ]),
        Scalar::from_raw([u64::MAX; 4])
    );

    assert_eq!(Scalar::from_raw(uint_to_raw(MODULUS)), Scalar::zero());

    assert_eq!(Scalar::from_raw([1, 0, 0, 0]), Scalar::one());
}

#[test]
fn test_from_canonical() {
    assert_eq!(
        Scalar::from_raw([
            0x0001_ffff_fffd,
            0x5884_b7fa_0003_4802,
            0x998c_4fef_ecbc_4ff5,
            0x1824_b159_acc5_056f,
        ]),
        Scalar::from_canonical(U256::MAX)
    );

    assert_eq!(Scalar::from_canonical(MODULUS), Scalar::zero());

    assert_eq!(Scalar::from_canonical(U256::ONE), Scalar::one());
}

#[test]
fn test_double() {
    let a = Scalar::from_raw([
        0x1fff_3231_233f_fffd,
        0x4884_b7fa_0003_4802,
        0x998c_4fef_ecbc_4ff3,
        0x1824_b159_acc5_0562,
    ]);

    assert_eq!(a.double(), a + a);
}

#[cfg(feature = "zeroize")]
#[test]
fn test_zeroize() {
    use zeroize::Zeroize;

    let mut a = Scalar::from_raw([
        0x1fff_3231_233f_fffd,
        0x4884_b7fa_0003_4802,
        0x998c_4fef_ecbc_4ff3,
        0x1824_b159_acc5_0562,
    ]);
    a.zeroize();
    assert!(bool::from(a.is_zero()));
}
