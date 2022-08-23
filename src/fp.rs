//! This module provides an implementation of the BLS12-381 base field `GF(p)`
//! where `p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab`

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use crypto_bigint::{nlimbs, CheckedSub, Encoding, UInt, Zero, U384};
use rand_core::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use crate::util::Montgomery;

type Inner = U384;

// The internal representation of this type is six 64-bit unsigned
// integers in little-endian order. `Fp` values are always in
// Montgomery form; i.e., Scalar(a) = aR mod p, with R = 2^384.
#[derive(Copy, Clone, Eq)]
#[repr(transparent)]
pub struct Fp(pub(crate) Inner);

impl fmt::Debug for Fp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tmp = self.to_bytes();
        write!(f, "0x")?;
        for &b in tmp.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl Default for Fp {
    fn default() -> Self {
        Fp::zero()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for Fp {}

impl ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Fp {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl ConditionallySelectable for Fp {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp(Inner::conditional_select(&a.0, &b.0, choice))
    }
}

/// The field definition with associated helper functions.
const FIELD: Montgomery<{ nlimbs!(384) }> = Montgomery::new(Inner::from_be_hex(
    "1a0111ea397fe69a\
     4b1ba7b6434bacd7\
     64774b84f38512bf\
     6730d2a0f6b0f624\
     1eabfffeb153ffff\
     b9feffffffffaaab",
));

impl<'a> Neg for &'a Fp {
    type Output = Fp;

    #[inline]
    fn neg(self) -> Fp {
        self.neg()
    }
}

impl Neg for Fp {
    type Output = Fp;

    #[inline]
    fn neg(self) -> Fp {
        -&self
    }
}

impl<'a, 'b> Sub<&'b Fp> for &'a Fp {
    type Output = Fp;

    #[inline]
    fn sub(self, rhs: &'b Fp) -> Fp {
        self.sub(rhs)
    }
}

impl<'a, 'b> Add<&'b Fp> for &'a Fp {
    type Output = Fp;

    #[inline]
    fn add(self, rhs: &'b Fp) -> Fp {
        self.add(rhs)
    }
}

impl<'a, 'b> Mul<&'b Fp> for &'a Fp {
    type Output = Fp;

    #[inline]
    fn mul(self, rhs: &'b Fp) -> Fp {
        self.mul(rhs)
    }
}

impl_binops_additive!(Fp, Fp);
impl_binops_multiplicative!(Fp, Fp);

impl Fp {
    /// Returns zero, the additive identity.
    #[inline]
    pub const fn zero() -> Fp {
        Fp(Inner::ZERO)
    }

    /// Returns one, the multiplicative identity.
    #[inline]
    pub const fn one() -> Fp {
        Fp(FIELD.one())
    }

    #[inline]
    pub fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    /// Attempts to convert a big-endian byte representation of
    /// a scalar into an `Fp`, failing if the input is not canonical.
    pub fn from_bytes(bytes: &[u8; 48]) -> CtOption<Fp> {
        FIELD
            .try_from_canonical(&Inner::from_be_bytes(*bytes))
            .map(|s| Fp(s))
    }

    /// Converts an element of `Fp` into a byte representation in
    /// big-endian byte order.
    pub fn to_bytes(self) -> [u8; 48] {
        self.to_canonical().to_be_bytes()
    }

    /// Converts a 768-bit little endian integer into a `Fp` by
    /// reducing by the modulus.
    pub fn from_bytes_wide(bytes: &[u8; 96]) -> Self {
        let lo = Inner::from_le_bytes(bytes[0..48].try_into().unwrap());
        let hi = Inner::from_le_bytes(bytes[48..96].try_into().unwrap());
        Fp(FIELD.from_canonical_wide(lo, hi))
    }

    /// Converts from a canonical element represented by a U384.
    #[inline]
    #[allow(unused)]
    pub(crate) const fn from_canonical(val: Inner) -> Self {
        Fp(FIELD.from_canonical(&val))
    }

    /// Turn into canonical form by computing
    /// (a.R) / R = a
    #[inline]
    pub(crate) const fn to_canonical(&self) -> Inner {
        FIELD.to_canonical(&self.0)
    }

    pub(crate) fn random(mut rng: impl RngCore) -> Fp {
        let mut bytes = [0u8; 96];
        rng.fill_bytes(&mut bytes);
        Fp::from_bytes_wide(&bytes)
    }

    /// Returns whether or not this element is strictly lexicographically
    /// larger than its negation.
    pub fn lexicographically_largest(&self) -> Choice {
        // This can be determined by checking to see if the element is
        // larger than (p - 1) // 2. If we subtract by ((p - 1) // 2) + 1
        // and there is no underflow, then the element must be larger than
        // (p - 1) // 2.
        const SUB_BY: Inner = Inner::from_be_hex(
            "0d0088f51cbff34d\
             258dd3db21a5d66b\
             b23ba5c279c2895f\
             b39869507b587b12\
             0f55ffff58a9ffff\
             dcff7fffffffd556",
        );

        // First, because self is in Montgomery form we need to reduce it
        let tmp = self.to_canonical();

        // The checked sub will be defined when tmp >= SUB_BY.
        tmp.checked_sub(&SUB_BY).is_some()
    }

    /// Constructs an element of `Fp` without checking that it is
    /// canonical.
    pub const fn from_raw_unchecked(v: [u64; 6]) -> Fp {
        Fp(inner_from_raw(v))
    }

    #[inline]
    #[allow(unused)]
    pub(crate) const fn to_raw(&self) -> [u64; 6] {
        inner_to_raw(self.0)
    }

    /// Although this is labeled "vartime", it is only
    /// variable time with respect to the exponent. It
    /// is also not exposed in the public API.
    pub const fn pow_vartime<const T: usize>(&self, by: &UInt<T>) -> Self {
        Fp(FIELD.pow_vartime(&self.0, by))
    }

    #[inline]
    pub fn sqrt(&self) -> CtOption<Self> {
        // We use Shank's method, as p = 3 (mod 4). This means
        // we only need to exponentiate by (p+1)/4. This only
        // works for elements that are actually quadratic residue,
        // so we check that we got the correct result at the end.
        const EXP: Inner = Inner::from_be_hex(
            "0680447a8e5ff9a6\
             92c6e9ed90d2eb35\
             d91dd2e13ce144af\
             d9cc34a83dac3d89\
             07aaffffac54ffff\
             ee7fbfffffffeaab",
        );

        let sqrt = self.pow_vartime(&EXP);

        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }

    #[inline]
    /// Computes the multiplicative inverse of this field
    /// element, returning None in the case that this element
    /// is zero.
    pub fn invert(&self) -> CtOption<Self> {
        // Exponentiate by p - 2
        const EXP: Inner = Inner::from_be_hex(
            "1a0111ea397fe69a\
             4b1ba7b6434bacd7\
             64774b84f38512bf\
             6730d2a0f6b0f624\
             1eabfffeb153ffff\
             b9feffffffffaaa9",
        );

        let inv = self.pow_vartime(&EXP);

        CtOption::new(inv, !self.is_zero())
    }

    #[inline]
    pub const fn add(&self, rhs: &Fp) -> Fp {
        Fp(FIELD.add(&self.0, &rhs.0))
    }

    #[inline]
    pub const fn double(&self) -> Fp {
        Fp(FIELD.double(&self.0))
    }

    #[inline]
    pub const fn neg(&self) -> Fp {
        Fp(FIELD.neg(&self.0))
    }

    #[inline]
    pub const fn sub(&self, rhs: &Fp) -> Fp {
        Fp(FIELD.sub(&self.0, &rhs.0))
    }

    /// Returns `c = a.zip(b).fold(0, |acc, (a_i, b_i)| acc + a_i * b_i)`.
    #[inline]
    pub(crate) fn sum_of_products<const T: usize>(a: [Fp; T], b: [Fp; T]) -> Fp {
        #[allow(unsafe_code)]
        let ar = unsafe { &*((&a) as *const Fp as *const [Inner; T]) };
        #[allow(unsafe_code)]
        let br = unsafe { &*((&b) as *const Fp as *const [Inner; T]) };
        return Fp(FIELD.sum_of_products(ar, br));
    }

    #[inline]
    pub const fn mul(&self, rhs: &Fp) -> Fp {
        Fp(FIELD.mul(&self.0, &rhs.0))
    }

    /// Squares this element.
    #[inline]
    pub const fn square(&self) -> Self {
        Fp(FIELD.square(&self.0))
    }
}

#[inline]
#[cfg(target_pointer_width = "32")]
const fn inner_from_raw(arr: [u64; 6]) -> Inner {
    const MASK: u64 = u32::MAX as u64;
    Inner::from_words([
        (arr[0] & MASK) as u32,
        (arr[0] >> 32) as u32,
        (arr[1] & MASK) as u32,
        (arr[1] >> 32) as u32,
        (arr[2] & MASK) as u32,
        (arr[2] >> 32) as u32,
        (arr[3] & MASK) as u32,
        (arr[3] >> 32) as u32,
        (arr[4] & MASK) as u32,
        (arr[4] >> 32) as u32,
        (arr[5] & MASK) as u32,
        (arr[5] >> 32) as u32,
    ])
}

#[inline]
#[cfg(target_pointer_width = "64")]
const fn inner_from_raw(arr: [u64; 6]) -> Inner {
    Inner::from_words(arr)
}

#[inline]
#[cfg(target_pointer_width = "32")]
const fn inner_to_raw(uint: Inner) -> [u64; 6] {
    let words = uint.as_words();
    [
        (words[0] as u64) | ((words[1] as u64) << 32),
        (words[2] as u64) | ((words[3] as u64) << 32),
        (words[4] as u64) | ((words[5] as u64) << 32),
        (words[6] as u64) | ((words[7] as u64) << 32),
        (words[8] as u64) | ((words[9] as u64) << 32),
        (words[10] as u64) | ((words[11] as u64) << 32),
    ]
}

#[inline]
#[cfg(target_pointer_width = "64")]
const fn inner_to_raw(uint: Inner) -> [u64; 6] {
    uint.to_words()
}

#[test]
fn test_inv() {
    // Compute -(q^{-1} mod 2^{Limb::BIT_SIZE}) mod 2^{Limb::BIT_SIZE} by
    // exponentiating by totient(2**{Limb::BIT_SIZE}) - 1
    use crypto_bigint::Limb;

    let mut inv = Limb::ONE;
    for _ in 0..(Limb::BIT_SIZE - 1) {
        inv = inv.wrapping_mul(inv);
        inv = inv.wrapping_mul(FIELD.modulus.limbs()[0]);
    }
    inv = Limb::ZERO.wrapping_sub(inv);
    assert_eq!(inv, FIELD.inv);
}

#[test]
fn test_conditional_selection() {
    let a = Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6]);
    let b = Fp::from_raw_unchecked([7, 8, 9, 10, 11, 12]);

    assert_eq!(
        ConditionallySelectable::conditional_select(&a, &b, Choice::from(0u8)),
        a
    );
    assert_eq!(
        ConditionallySelectable::conditional_select(&a, &b, Choice::from(1u8)),
        b
    );
}

#[test]
fn test_equality() {
    fn is_equal(a: &Fp, b: &Fp) -> bool {
        let eq = a == b;
        let ct_eq = a.ct_eq(&b);

        assert_eq!(eq, bool::from(ct_eq));

        eq
    }

    assert!(is_equal(
        &Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6]),
        &Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6])
    ));

    assert!(!is_equal(
        &Fp::from_raw_unchecked([7, 2, 3, 4, 5, 6]),
        &Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6])
    ));
    assert!(!is_equal(
        &Fp::from_raw_unchecked([1, 7, 3, 4, 5, 6]),
        &Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6])
    ));
    assert!(!is_equal(
        &Fp::from_raw_unchecked([1, 2, 7, 4, 5, 6]),
        &Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6])
    ));
    assert!(!is_equal(
        &Fp::from_raw_unchecked([1, 2, 3, 7, 5, 6]),
        &Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6])
    ));
    assert!(!is_equal(
        &Fp::from_raw_unchecked([1, 2, 3, 4, 7, 6]),
        &Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6])
    ));
    assert!(!is_equal(
        &Fp::from_raw_unchecked([1, 2, 3, 4, 5, 7]),
        &Fp::from_raw_unchecked([1, 2, 3, 4, 5, 6])
    ));
}

#[test]
fn test_squaring() {
    let a = Fp::from_raw_unchecked([
        0xd215_d276_8e83_191b,
        0x5085_d80f_8fb2_8261,
        0xce9a_032d_df39_3a56,
        0x3e9c_4fff_2ca0_c4bb,
        0x6436_b6f7_f4d9_5dfb,
        0x1060_6628_ad4a_4d90,
    ]);
    let b = Fp::from_raw_unchecked([
        0x33d9_c42a_3cb3_e235,
        0xdad1_1a09_4c4c_d455,
        0xa2f1_44bd_729a_aeba,
        0xd415_0932_be9f_feac,
        0xe27b_c7c4_7d44_ee50,
        0x14b6_a78d_3ec7_a560,
    ]);

    assert_eq!(a.square(), b);
}

#[test]
fn test_multiplication() {
    let a = Fp::from_raw_unchecked([
        0x0397_a383_2017_0cd4,
        0x734c_1b2c_9e76_1d30,
        0x5ed2_55ad_9a48_beb5,
        0x095a_3c6b_22a7_fcfc,
        0x2294_ce75_d4e2_6a27,
        0x1333_8bd8_7001_1ebb,
    ]);
    let b = Fp::from_raw_unchecked([
        0xb9c3_c7c5_b119_6af7,
        0x2580_e208_6ce3_35c1,
        0xf49a_ed3d_8a57_ef42,
        0x41f2_81e4_9846_e878,
        0xe076_2346_c384_52ce,
        0x0652_e893_26e5_7dc0,
    ]);
    let c = Fp::from_raw_unchecked([
        0xf96e_f3d7_11ab_5355,
        0xe8d4_59ea_00f1_48dd,
        0x53f7_354a_5f00_fa78,
        0x9e34_a4f3_125c_5f83,
        0x3fbe_0c47_ca74_c19e,
        0x01b0_6a8b_bd4a_dfe4,
    ]);

    assert_eq!(a * b, c);
}

#[test]
fn test_addition() {
    let a = Fp::from_raw_unchecked([
        0x5360_bb59_7867_8032,
        0x7dd2_75ae_799e_128e,
        0x5c5b_5071_ce4f_4dcf,
        0xcdb2_1f93_078d_bb3e,
        0xc323_65c5_e73f_474a,
        0x115a_2a54_89ba_be5b,
    ]);
    let b = Fp::from_raw_unchecked([
        0x9fd2_8773_3d23_dda0,
        0xb16b_f2af_738b_3554,
        0x3e57_a75b_d3cc_6d1d,
        0x900b_c0bd_627f_d6d6,
        0xd319_a080_efb2_45fe,
        0x15fd_caa4_e4bb_2091,
    ]);
    let c = Fp::from_raw_unchecked([
        0x3934_42cc_b58b_b327,
        0x1092_685f_3bd5_47e3,
        0x3382_252c_ab6a_c4c9,
        0xf946_94cb_7688_7f55,
        0x4b21_5e90_93a5_e071,
        0x0d56_e30f_34f5_f853,
    ]);

    assert_eq!(a + b, c);
}

#[test]
fn test_subtraction() {
    let a = Fp::from_raw_unchecked([
        0x5360_bb59_7867_8032,
        0x7dd2_75ae_799e_128e,
        0x5c5b_5071_ce4f_4dcf,
        0xcdb2_1f93_078d_bb3e,
        0xc323_65c5_e73f_474a,
        0x115a_2a54_89ba_be5b,
    ]);
    let b = Fp::from_raw_unchecked([
        0x9fd2_8773_3d23_dda0,
        0xb16b_f2af_738b_3554,
        0x3e57_a75b_d3cc_6d1d,
        0x900b_c0bd_627f_d6d6,
        0xd319_a080_efb2_45fe,
        0x15fd_caa4_e4bb_2091,
    ]);
    let c = Fp::from_raw_unchecked([
        0x6d8d_33e6_3b43_4d3d,
        0xeb12_82fd_b766_dd39,
        0x8534_7bb6_f133_d6d5,
        0xa21d_aa5a_9892_f727,
        0x3b25_6cfb_3ad8_ae23,
        0x155d_7199_de7f_8464,
    ]);

    assert_eq!(a - b, c);
}

#[test]
fn test_negation() {
    let a = Fp::from_raw_unchecked([
        0x5360_bb59_7867_8032,
        0x7dd2_75ae_799e_128e,
        0x5c5b_5071_ce4f_4dcf,
        0xcdb2_1f93_078d_bb3e,
        0xc323_65c5_e73f_474a,
        0x115a_2a54_89ba_be5b,
    ]);
    let b = Fp::from_raw_unchecked([
        0x669e_44a6_8798_2a79,
        0xa0d9_8a50_37b5_ed71,
        0x0ad5_822f_2861_a854,
        0x96c5_2bf1_ebf7_5781,
        0x87f8_41f0_5c0c_658c,
        0x08a6_e795_afc5_283e,
    ]);

    assert_eq!(-a, b);
}

#[test]
fn test_debug() {
    assert_eq!(
        format!(
            "{:?}",
            Fp::from_raw_unchecked([
                0x5360_bb59_7867_8032,
                0x7dd2_75ae_799e_128e,
                0x5c5b_5071_ce4f_4dcf,
                0xcdb2_1f93_078d_bb3e,
                0xc323_65c5_e73f_474a,
                0x115a_2a54_89ba_be5b,
            ])
        ),
        "0x104bf052ad3bc99bcb176c24a06a6c3aad4eaf2308fc4d282e106c84a757d061052630515305e59bdddf8111bfdeb704"
    );
}

#[test]
fn test_from_bytes() {
    let mut a = Fp::from_raw_unchecked([
        0xdc90_6d9b_e3f9_5dc8,
        0x8755_caf7_4596_91a1,
        0xcff1_a7f4_e958_3ab3,
        0x9b43_821f_849e_2284,
        0xf575_54f3_a297_4f3f,
        0x085d_bea8_4ed4_7f79,
    ]);

    for _ in 0..100 {
        a = a.square();
        let tmp = a.to_bytes();
        let b = Fp::from_bytes(&tmp).unwrap();

        assert_eq!(a, b);
    }

    assert_eq!(
        -Fp::one(),
        Fp::from_bytes(&[
            26, 1, 17, 234, 57, 127, 230, 154, 75, 27, 167, 182, 67, 75, 172, 215, 100, 119, 75,
            132, 243, 133, 18, 191, 103, 48, 210, 160, 246, 176, 246, 36, 30, 171, 255, 254, 177,
            83, 255, 255, 185, 254, 255, 255, 255, 255, 170, 170
        ])
        .unwrap()
    );

    assert!(bool::from(
        Fp::from_bytes(&[
            27, 1, 17, 234, 57, 127, 230, 154, 75, 27, 167, 182, 67, 75, 172, 215, 100, 119, 75,
            132, 243, 133, 18, 191, 103, 48, 210, 160, 246, 176, 246, 36, 30, 171, 255, 254, 177,
            83, 255, 255, 185, 254, 255, 255, 255, 255, 170, 170
        ])
        .is_none()
    ));

    assert!(bool::from(Fp::from_bytes(&[0xff; 48]).is_none()));
}

#[test]
fn test_sqrt() {
    // a = 4
    let a = Fp::from_raw_unchecked([
        0xaa27_0000_000c_fff3,
        0x53cc_0032_fc34_000a,
        0x478f_e97a_6b0a_807f,
        0xb1d3_7ebe_e6ba_24d7,
        0x8ec9_733b_bf78_ab2f,
        0x09d6_4551_3d83_de7e,
    ]);

    assert_eq!(
        // sqrt(4) = -2
        -a.sqrt().unwrap(),
        // 2
        Fp::from_raw_unchecked([
            0x3213_0000_0006_554f,
            0xb93c_0018_d6c4_0005,
            0x5760_5e0d_b0dd_bb51,
            0x8b25_6521_ed1f_9bcb,
            0x6cf2_8d79_0162_2c03,
            0x11eb_ab9d_bb81_e28c,
        ])
    );
}

#[test]
fn test_inversion() {
    let a = Fp::from_raw_unchecked([
        0x43b4_3a50_78ac_2076,
        0x1ce0_7630_46f8_962b,
        0x724a_5276_486d_735c,
        0x6f05_c2a6_282d_48fd,
        0x2095_bd5b_b4ca_9331,
        0x03b3_5b38_94b0_f7da,
    ]);
    let b = Fp::from_raw_unchecked([
        0x69ec_d704_0952_148f,
        0x985c_cc20_2219_0f55,
        0xe19b_ba36_a9ad_2f41,
        0x19bb_16c9_5219_dbd8,
        0x14dc_acfd_fb47_8693,
        0x115f_f58a_fff9_a8e1,
    ]);

    assert_eq!(a.invert().unwrap(), b);
    assert!(bool::from(Fp::zero().invert().is_none()));
}

#[test]
fn test_lexicographic_largest() {
    assert!(!bool::from(Fp::zero().lexicographically_largest()));
    assert!(!bool::from(Fp::one().lexicographically_largest()));
    assert!(!bool::from(
        Fp::from_raw_unchecked([
            0xa1fa_ffff_fffe_5557,
            0x995b_fff9_76a3_fffe,
            0x03f4_1d24_d174_ceb4,
            0xf654_7998_c199_5dbd,
            0x778a_468f_507a_6034,
            0x0205_5993_1f7f_8103
        ])
        .lexicographically_largest()
    ));
    assert!(bool::from(
        Fp::from_raw_unchecked([
            0x1804_0000_0001_5554,
            0x8550_0005_3ab0_0001,
            0x633c_b57c_253c_276f,
            0x6e22_d1ec_31eb_b502,
            0xd391_6126_f2d1_4ca2,
            0x17fb_b857_1a00_6596,
        ])
        .lexicographically_largest()
    ));
    assert!(bool::from(
        Fp::from_raw_unchecked([
            0x43f5_ffff_fffc_aaae,
            0x32b7_fff2_ed47_fffd,
            0x07e8_3a49_a2e9_9d69,
            0xeca8_f331_8332_bb7a,
            0xef14_8d1e_a0f4_c069,
            0x040a_b326_3eff_0206,
        ])
        .lexicographically_largest()
    ));
}

#[cfg(feature = "zeroize")]
#[test]
fn test_zeroize() {
    use zeroize::Zeroize;

    let mut a = Fp::one();
    a.zeroize();
    assert!(bool::from(a.is_zero()));
}
