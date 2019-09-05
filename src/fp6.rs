use crate::fp::*;
use crate::fp2::*;

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// This represents an element $c_0 + c_1 v + c_2 v^2$ of $\mathbb{F}_{p^6} = \mathbb{F}_{p^2} / v^3 - u - 1$.
pub struct Fp6 {
    pub c0: Fp2,
    pub c1: Fp2,
    pub c2: Fp2,
}

impl From<Fp> for Fp6 {
    fn from(f: Fp) -> Fp6 {
        Fp6 {
            c0: Fp2::from(f),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }
}

impl From<Fp2> for Fp6 {
    fn from(f: Fp2) -> Fp6 {
        Fp6 {
            c0: f,
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }
}

impl PartialEq for Fp6 {
    fn eq(&self, other: &Fp6) -> bool {
        self.ct_eq(other).into()
    }
}

impl Copy for Fp6 {}
impl Clone for Fp6 {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl Default for Fp6 {
    fn default() -> Self {
        Fp6::zero()
    }
}

impl fmt::Debug for Fp6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} + ({:?})*v + ({:?})*v^2", self.c0, self.c1, self.c2)
    }
}

impl ConditionallySelectable for Fp6 {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp6 {
            c0: Fp2::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp2::conditional_select(&a.c1, &b.c1, choice),
            c2: Fp2::conditional_select(&a.c2, &b.c2, choice),
        }
    }
}

impl ConstantTimeEq for Fp6 {
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0) & self.c1.ct_eq(&other.c1) & self.c2.ct_eq(&other.c2)
    }
}

impl Fp6 {
    #[inline]
    pub fn zero() -> Self {
        Fp6 {
            c0: Fp2::zero(),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }

    #[inline]
    pub fn one() -> Self {
        Fp6 {
            c0: Fp2::one(),
            c1: Fp2::zero(),
            c2: Fp2::zero(),
        }
    }

    pub fn mul_by_1(&self, c1: &Fp2) -> Fp6 {
        let b_b = self.c1 * c1;

        let t1 = (self.c1 + self.c2) * c1 - b_b;
        let t1 = t1.mul_by_nonresidue();

        let t2 = (self.c0 + self.c1) * c1 - b_b;

        Fp6 {
            c0: t1,
            c1: t2,
            c2: b_b,
        }
    }

    pub fn mul_by_01(&self, c0: &Fp2, c1: &Fp2) -> Fp6 {
        let a_a = self.c0 * c0;
        let b_b = self.c1 * c1;

        let t1 = (self.c1 + self.c2) * c1 - b_b;
        let t1 = t1.mul_by_nonresidue() + a_a;

        let t2 = (c0 + c1) * (self.c0 + self.c1) - a_a - b_b;

        let t3 = (self.c0 + self.c2) * c0 - a_a + b_b;

        Fp6 {
            c0: t1,
            c1: t2,
            c2: t3,
        }
    }

    /// Multiply by quadratic nonresidue v.
    pub fn mul_by_nonresidue(&self) -> Self {
        // Given a + bv + cv^2, this produces
        //     av + bv^2 + cv^3
        // but because v^3 = u + 1, we have
        //     c(u + 1) + av + v^2

        Fp6 {
            c0: self.c2.mul_by_nonresidue(),
            c1: self.c0,
            c2: self.c1,
        }
    }

    /// Returns whether or not this element is strictly lexicographically
    /// larger than its negation.
    #[inline]
    pub fn lexicographically_largest(&self) -> Choice {
        // If this element's c1 coefficient is lexicographically largest
        // then it is lexicographically largest. Otherwise, in the event
        // the c1 coefficient is zero and the c0 coefficient is
        // lexicographically largest, then this element is lexicographically
        // largest.

        self.c1.lexicographically_largest()
            | (self.c1.is_zero() & self.c0.lexicographically_largest())
    }

    /// Raises this element to p.
    #[inline(always)]
    pub fn frobenius_map(&self) -> Self {
        let c0 = self.c0.frobenius_map();
        let c1 = self.c1.frobenius_map();
        let c2 = self.c2.frobenius_map();

        // c1 = c1 * (u + 1)^((p - 1) / 3)
        let c1 = c1
            * Fp2 {
                c0: Fp::zero(),
                c1: Fp::from_raw_unchecked([
                    0xcd03c9e48671f071,
                    0x5dab22461fcda5d2,
                    0x587042afd3851b95,
                    0x8eb60ebe01bacb9e,
                    0x3f97d6e83d050d2,
                    0x18f0206554638741,
                ]),
            };

        // c2 = c2 * (u + 1)^((2p - 2) / 3)
        let c2 = c2
            * Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x890dc9e4867545c3,
                    0x2af322533285a5d5,
                    0x50880866309b7e2c,
                    0xa20d1b8c7e881024,
                    0x14e4f04fe2db9068,
                    0x14e56d3f1564853a,
                ]),
                c1: Fp::zero(),
            };

        Fp6 { c0, c1, c2 }
    }

    #[inline(always)]
    pub fn is_zero(&self) -> Choice {
        self.c0.is_zero() & self.c1.is_zero() & self.c2.is_zero()
    }

    #[inline]
    pub fn square(&self) -> Self {
        let s0 = self.c0.square();
        let ab = self.c0 * self.c1;
        let s1 = ab + ab;
        let s2 = (self.c0 - self.c1 + self.c2).square();
        let bc = self.c1 * self.c2;
        let s3 = bc + bc;
        let s4 = self.c2.square();

        Fp6 {
            c0: s3.mul_by_nonresidue() + s0,
            c1: s4.mul_by_nonresidue() + s1,
            c2: s1 + s2 + s3 - s0 - s4,
        }
    }

    /// Square root
    ///
    /// As described by:
    /// "On the Computation of Square Roots in Finite Fields", proposition 2.1
    /// By Siguna Müller, 2004
    ///
    /// Uses the fact that p^6 = 9 mod 16.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Q_1_4 = (modulus^6 - 1) / 4
        const Q_1_4: [u64; 36] = [
            0xb1b26118f01c175a,
            0xf8a2683cfd2fcb7,
            0xf5ecead6e31ae561,
            0x788892a3ae5aaa66,
            0x6f1b989afdd74c6c,
            0x44b0febfb9ca2f19,
            0xaa44afead22b2a8c,
            0x44412b069787405b,
            0x1d4f314ef085b227,
            0xa3438bfd9d5dc836,
            0x3aca6af3d8e4c9cd,
            0x9233ff8daf86758b,
            0xf183aa79f6a23e1e,
            0x9285a7b5ef849914,
            0x3392479651e7cbc1,
            0xba3bd9bd93f0e78e,
            0x1681362d6278bb82,
            0xbf9fb30183701059,
            0x8e8e4f1c7eea8aa5,
            0xe0eba5f5b90a8877,
            0x82c196b55e440708,
            0x476387890d02af5e,
            0x733d7734aebdd85b,
            0x233beef2d2cc2a7b,
            0xfe1257e301d152ee,
            0x977cd3e02d91b8c0,
            0x1a7e36349a50bf5b,
            0xf734044b05c5b0a7,
            0x6455a14c3662f861,
            0xedea13251b5203df,
            0x714e2975915a9a71,
            0x817b0e2e3d10781d,
            0x52fd761dc052d57d,
            0x3c8b51fa3d322987,
            0x687d273175e44744,
            0x49b8ea73982,
        ];

        // Note: 2^((p^6-1)/4) = 1 in Fp6, so s^2 = self^((p^6-1)/2),
        // so Legendre-symbol, hence self is a quadratic residue iff s = 1 or s = -1.
        // TODO: use addition chains.
        let s = (self + self).pow_vartime(&Q_1_4);

        let v = Fp6 {
            c0: Fp2::zero(),
            c1: Fp2::one(),
            c2: Fp2::zero(),
        };

        let is_one = s.ct_eq(&Fp6::one());
        let is_neg_one = s.ct_eq(&-Fp6::one());

        let d = Fp6::conditional_select(&-Fp6::one(), &v, is_one);

        // Q_9_16 = (modulus^6 - 9) / 16
        const Q_9_16: [u64; 36] = [
            0xec6c98463c0705d6,
            0x43e289a0f3f4bf2d,
            0xbd7b3ab5b8c6b958,
            0x1e2224a8eb96aa99,
            0x5bc6e626bf75d31b,
            0x112c3fafee728bc6,
            0xea912bfab48acaa3,
            0xd1104ac1a5e1d016,
            0x8753cc53bc216c89,
            0x68d0e2ff6757720d,
            0xceb29abcf6393273,
            0xa48cffe36be19d62,
            0x3c60ea9e7da88f87,
            0x64a169ed7be12645,
            0x8ce491e59479f2f0,
            0xae8ef66f64fc39e3,
            0x45a04d8b589e2ee0,
            0x6fe7ecc060dc0416,
            0xe3a393c71fbaa2a9,
            0x383ae97d6e42a21d,
            0xa0b065ad579101c2,
            0xd1d8e1e24340abd7,
            0xdccf5dcd2baf7616,
            0x88cefbbcb4b30a9e,
            0x3f8495f8c07454bb,
            0xe5df34f80b646e30,
            0xc69f8d8d26942fd6,
            0x7dcd0112c1716c29,
            0xd91568530d98be18,
            0x7b7a84c946d480f7,
            0x5c538a5d6456a69c,
            0x605ec38b8f441e07,
            0xd4bf5d877014b55f,
            0xf22d47e8f4c8a61,
            0x9a1f49cc5d7911d1,
            0x126e3a9ce60,
        ];

        let dd = d * d;
        let ddx = dd * self;

        // TODO: use addition chains.
        let z = (ddx + ddx).pow_vartime(&Q_9_16);

        let hi = ddx * z * z;
        let i = hi + hi;

        let a = z * d * self * (i - Fp6::one());

        CtOption::new(a, is_one | is_neg_one)
    }

    #[inline]
    pub fn invert(&self) -> CtOption<Self> {
        let c0 = (self.c1 * self.c2).mul_by_nonresidue();
        let c0 = self.c0.square() - c0;

        let c1 = self.c2.square().mul_by_nonresidue();
        let c1 = c1 - (self.c0 * self.c1);

        let c2 = self.c1.square();
        let c2 = c2 - (self.c0 * self.c2);

        let tmp = ((self.c1 * c2) + (self.c2 * c1)).mul_by_nonresidue();
        let tmp = tmp + (self.c0 * c0);

        tmp.invert().map(|t| Fp6 {
            c0: t * c0,
            c1: t * c1,
            c2: t * c2,
        })
    }

    /// Although this is labeled "vartime", it is only
    /// variable time with respect to the exponent. It
    /// is also not exposed in the public API.
    pub fn pow_vartime(&self, by: &[u64]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();

                if ((*e >> i) & 1) == 1 {
                    res *= self;
                }
            }
        }
        res
    }

    /// Attempts to convert a little-endian byte representation of
    /// a scalar into an `Fp6`.
    ///
    /// Only fails when the underlying Fp elements are not canonical,
    /// but not when `Fp6` is not part of the subgroup.
    pub fn from_bytes_unchecked(bytes: &[u8; 288]) -> CtOption<Fp6> {
        let mut buf = [0u8; 96];

        buf.copy_from_slice(&bytes[0..96]);
        let c0 = Fp2::from_bytes_unchecked(&buf);
        buf.copy_from_slice(&bytes[96..192]);
        let c1 = Fp2::from_bytes_unchecked(&buf);
        buf.copy_from_slice(&bytes[192..288]);
        let c2 = Fp2::from_bytes_unchecked(&buf);

        c0.and_then(|c0| c1.and_then(|c1| c2.map(|c2| Fp6 { c0, c1, c2 })))
    }

    /// Converts an element of `Fp6` into a byte representation in
    /// big-endian byte order.
    pub fn to_bytes(&self) -> [u8; 288] {
        let mut res = [0; 288];

        res[0..96].copy_from_slice(&self.c0.to_bytes());
        res[96..192].copy_from_slice(&self.c1.to_bytes());
        res[192..288].copy_from_slice(&self.c2.to_bytes());

        res
    }
}

impl<'a, 'b> Mul<&'b Fp6> for &'a Fp6 {
    type Output = Fp6;

    #[inline]
    fn mul(self, other: &'b Fp6) -> Self::Output {
        let aa = self.c0 * other.c0;
        let bb = self.c1 * other.c1;
        let cc = self.c2 * other.c2;

        let t1 = other.c1 + other.c2;
        let tmp = self.c1 + self.c2;
        let t1 = t1 * tmp;
        let t1 = t1 - bb;
        let t1 = t1 - cc;
        let t1 = t1.mul_by_nonresidue();
        let t1 = t1 + aa;

        let t3 = other.c0 + other.c2;
        let tmp = self.c0 + self.c2;
        let t3 = t3 * tmp;
        let t3 = t3 - aa;
        let t3 = t3 + bb;
        let t3 = t3 - cc;

        let t2 = other.c0 + other.c1;
        let tmp = self.c0 + self.c1;
        let t2 = t2 * tmp;
        let t2 = t2 - aa;
        let t2 = t2 - bb;
        let cc = cc.mul_by_nonresidue();
        let t2 = t2 + cc;

        Fp6 {
            c0: t1,
            c1: t2,
            c2: t3,
        }
    }
}

impl<'a, 'b> Add<&'b Fp6> for &'a Fp6 {
    type Output = Fp6;

    #[inline]
    fn add(self, rhs: &'b Fp6) -> Self::Output {
        Fp6 {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

impl<'a> Neg for &'a Fp6 {
    type Output = Fp6;

    #[inline]
    fn neg(self) -> Self::Output {
        Fp6 {
            c0: -self.c0,
            c1: -self.c1,
            c2: -self.c2,
        }
    }
}

impl Neg for Fp6 {
    type Output = Fp6;

    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl<'a, 'b> Sub<&'b Fp6> for &'a Fp6 {
    type Output = Fp6;

    #[inline]
    fn sub(self, rhs: &'b Fp6) -> Self::Output {
        Fp6 {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
            c2: self.c2 - rhs.c2,
        }
    }
}

impl_binops_additive!(Fp6, Fp6);
impl_binops_multiplicative!(Fp6, Fp6);

#[test]
fn test_arithmetic() {
    use crate::fp::*;

    let a = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x47f9cb98b1b82d58,
                0x5fe911eba3aa1d9d,
                0x96bf1b5f4dd81db3,
                0x8100d27cc9259f5b,
                0xafa20b9674640eab,
                0x9bbcea7d8d9497d,
            ]),
            c1: Fp::from_raw_unchecked([
                0x303cb98b1662daa,
                0xd93110aa0a621d5a,
                0xbfa9820c5be4a468,
                0xba3643ecb05a348,
                0xdc3534bb1f1c25a6,
                0x6c305bb19c0e1c1,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x46f9cb98b162d858,
                0xbe9109cf7aa1d57,
                0xc791bc55fece41d2,
                0xf84c57704e385ec2,
                0xcb49c1d9c010e60f,
                0xacdb8e158bfe3c8,
            ]),
            c1: Fp::from_raw_unchecked([
                0x8aefcb98b15f8306,
                0x3ea1108fe4f21d54,
                0xcf79f69fa1b7df3b,
                0xe4f54aa1d16b1a3c,
                0xba5e4ef86105a679,
                0xed86c0797bee5cf,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xcee5cb98b15c2db4,
                0x71591082d23a1d51,
                0xd76230e944a17ca4,
                0xd19e3dd3549dd5b6,
                0xa972dc1701fa66e3,
                0x12e31f2dd6bde7d6,
            ]),
            c1: Fp::from_raw_unchecked([
                0xad2acb98b1732d9d,
                0x2cfd10dd06961d64,
                0x7396b86c6ef24e8,
                0xbd76e2fdb1bfc820,
                0x6afea7f6de94d0d5,
                0x10994b0c5744c040,
            ]),
        },
    };

    let b = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xf120cb98b16fd84b,
                0x5fb510cff3de1d61,
                0xf21a5d069d8c251,
                0xaa1fd62f34f2839a,
                0x5a1335157f89913f,
                0x14a3fe329643c247,
            ]),
            c1: Fp::from_raw_unchecked([
                0x3516cb98b16c82f9,
                0x926d10c2e1261d5f,
                0x1709e01a0cc25fba,
                0x96c8c960b8253f14,
                0x4927c234207e51a9,
                0x18aeb158d542c44e,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xbf0dcb98b16982fc,
                0xa67910b71d1a1d5c,
                0xb7c147c2b8fb06ff,
                0x1efa710d47d2e7ce,
                0xed20a79c7e27653c,
                0x2b85294dac1dfba,
            ]),
            c1: Fp::from_raw_unchecked([
                0x9d52cb98b18082e5,
                0x621d111151761d6f,
                0xe79882603b48af43,
                0xad31637a4f4da37,
                0xaeac737c5ac1cf2e,
                0x6e7e735b48b824,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xe148cb98b17d2d93,
                0x94d511043ebe1d6c,
                0xef80bca9de324cac,
                0xf77c0969282795b1,
                0x9dc1009afbb68f97,
                0x47931999a47ba2b,
            ]),
            c1: Fp::from_raw_unchecked([
                0x253ecb98b179d841,
                0xc78d10f72c061d6a,
                0xf768f6f3811bea15,
                0xe424fc9aab5a512b,
                0x8cd58db99cab5001,
                0x883e4bfd946bc32,
            ]),
        },
    };

    let c = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x6934cb98b17682ef,
                0xfa4510ea194e1d67,
                0xff51313d2405877e,
                0xd0cdefcc2e8d0ca5,
                0x7bea1ad83da0106b,
                0xc8e97e61845be39,
            ]),
            c1: Fp::from_raw_unchecked([
                0x4779cb98b18d82d8,
                0xb5e911444daa1d7a,
                0x2f286bdaa6532fc2,
                0xbca694f68baeff0f,
                0x3d75e6b81a3a7a5d,
                0xa44c3c498cc96a3,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x8b6fcb98b18a2d86,
                0xe8a111373af21d77,
                0x3710a624493ccd2b,
                0xa94f88280ee1ba89,
                0x2c8a73d6bb2f3ac7,
                0xe4f76ead7cb98aa,
            ]),
            c1: Fp::from_raw_unchecked([
                0xcf65cb98b186d834,
                0x1b59112a283a1d74,
                0x3ef8e06dec266a95,
                0x95f87b5992147603,
                0x1b9f00f55c23fb31,
                0x125a2a1116ca9ab1,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x135bcb98b18382e2,
                0x4e11111d15821d72,
                0x46e11ab78f1007fe,
                0x82a16e8b1547317d,
                0xab38e13fd18bb9b,
                0x1664dd3755c99cb8,
            ]),
            c1: Fp::from_raw_unchecked([
                0xce65cb98b1318334,
                0xc7590fdb7c3a1d2e,
                0x6fcb81649d1c8eb3,
                0xd44004d1727356a,
                0x3746b738a7d0d296,
                0x136c144a96b134fc,
            ]),
        },
    };

    assert_eq!(a.square(), &a * &a);
    assert_eq!(b.square(), &b * &b);
    assert_eq!(c.square(), &c * &c);

    assert_eq!(
        (a + b) * c.square(),
        &(&(&c * &c) * &a) + &(&(&c * &c) * &b)
    );

    assert_eq!(
        &a.invert().unwrap() * &b.invert().unwrap(),
        (&a * &b).invert().unwrap()
    );
    assert_eq!(&a.invert().unwrap() * &a, Fp6::one());
}

#[test]
fn test_sqrt() {
    let a = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x615eaaf7e0049a1b,
                0x7db3249009df9588,
                0x5d9254c0f7ae87f1,
                0x14fee19cbfc1faca,
                0x3017e7271c83b32b,
                0xbdc34aaf515eb44,
            ]),
            c1: Fp::from_raw_unchecked([
                0x27e6b317a77e12d0,
                0x341b70fc95934deb,
                0x26bd37e4251442ab,
                0x8c7bf72e39756512,
                0x1d2a1377ffc35dd4,
                0x735f5a52f945f95,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x2b5775a7a21ba5ba,
                0x8b5c1025c7098c9f,
                0x4d29b1556a548261,
                0x7a045cbceb12c9f0,
                0x2324654df63d1675,
                0x1113123138f58432,
            ]),
            c1: Fp::from_raw_unchecked([
                0x3f4d0c00005dc31b,
                0xed1d44e80072a5b,
                0xfdeda4845c7115ed,
                0x6b8d8cd2f54986dd,
                0xa3de763c81254081,
                0x1030efee1d581ee4,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xf376d245bed59044,
                0x335afd18409563ee,
                0xd1ee1e7d2cfba1b4,
                0x17086c56016a6b2b,
                0x30c195f0664865a9,
                0x5bc0c3bef4e9565,
            ]),
            c1: Fp::from_raw_unchecked([
                0x29241b89771406dd,
                0x3b269017c337a140,
                0xcf0c50cfdf0fb818,
                0xf1a56e35e67614bd,
                0x373427c6e475ec5e,
                0x10ab1bd5fbed215d,
            ]),
        },
    };

    assert!(bool::from(a.sqrt().is_none()));

    let b = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x760900000002fffd,
                0xebf4000bc40c0002,
                0x5f48985753c758ba,
                0x77ce585370525745,
                0x5c071a97a256ec6d,
                0x15f65ec3fa80e493,
            ]),
            c1: Fp::from_raw_unchecked([
                0x321300000006554f,
                0xb93c0018d6c40005,
                0x57605e0db0ddbb51,
                0x8b256521ed1f9bcb,
                0x6cf28d7901622c03,
                0x11ebab9dbb81e28c,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xee1d00000009aaa1,
                0x86840025e97c0007,
                0x4f7823c40df41de8,
                0x9e7c71f069ece051,
                0x7dde005a606d6b99,
                0xde0f8777c82e085,
            ]),
            c1: Fp::from_raw_unchecked([
                0xaa270000000cfff3,
                0x53cc0032fc34000a,
                0x478fe97a6b0a807f,
                0xb1d37ebee6ba24d7,
                0x8ec9733bbf78ab2f,
                0x9d645513d83de7e,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x6631000000105545,
                0x211400400eec000d,
                0x3fa7af30c820e316,
                0xc52a8b8d6387695d,
                0x9fb4e61d1e83eac5,
                0x5cb922afe84dc77,
            ]),
            c1: Fp::from_raw_unchecked([
                0x223b00000013aa97,
                0xee5c004d21a40010,
                0x37bf74e7253745ac,
                0xd881985be054ade3,
                0xb0a058fe7d8f2a5b,
                0x1c0df04bf85da70,
            ]),
        },
    };
    let b_sqrt = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xdacab8ec196d0e90,
                0x87e85ab6ea88b979,
                0x3dfe939a4a365ef1,
                0x78d2523061125499,
                0x6fc4397c4dc7b39,
                0x178d99f425a98078,
            ]),
            c1: Fp::from_raw_unchecked([
                0x5f61615b4b6b9955,
                0xfa5b876c8ea831b5,
                0x3fd6d7cd22e2fb76,
                0x2d55c9a9feef3d0a,
                0x7adfaf601698839c,
                0xd2971c3c245dbdb,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xd1857aba9d3a5ad2,
                0xaa0fcc118b33fd83,
                0xdddf06c2cd76474b,
                0xf2ba6fae3c211902,
                0x81b879d941bf01e8,
                0x16efa6ec5c6ebf43,
            ]),
            c1: Fp::from_raw_unchecked([
                0x6b7a79f9320e4b80,
                0xf0d55c31e63117d6,
                0x9f0c4f9fbb78699e,
                0xffc9af394b9b8049,
                0xb76d97ef754a5ad,
                0xb5172e8b69f5596,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xf140b9d2f1e99c5e,
                0xc78982e4ca301b97,
                0x98f3a4b656f50198,
                0xaa310cb32c652865,
                0xcbee9785769731bb,
                0x16f81c9ea55bde91,
            ]),
            c1: Fp::from_raw_unchecked([
                0x83304d5cf6ddb3d0,
                0x3bc1eac936b91f3f,
                0x26009dc8b2afd880,
                0x3d88fa5fd4a3a1a7,
                0x524af7c39e6b675d,
                0x1460fef116f3d046,
            ]),
        },
    };

    assert_eq!(b_sqrt * b_sqrt, b);
    assert_eq!(b.sqrt().unwrap().square(), b);
    assert_eq!(b.sqrt().unwrap(), b_sqrt);

    let c = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xaa270000000cfff3,
                0x53cc0032fc34000a,
                0x478fe97a6b0a807f,
                0xb1d37ebee6ba24d7,
                0x8ec9733bbf78ab2f,
                0x9d645513d83de7e,
            ]),
            c1: Fp::from_raw_unchecked([
                0x321300000006554f,
                0xb93c0018d6c40005,
                0x57605e0db0ddbb51,
                0x8b256521ed1f9bcb,
                0x6cf28d7901622c03,
                0x11ebab9dbb81e28c,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xee1d00000009aaa1,
                0x86840025e97c0007,
                0x4f7823c40df41de8,
                0x9e7c71f069ece051,
                0x7dde005a606d6b99,
                0xde0f8777c82e085,
            ]),
            c1: Fp::from_raw_unchecked([
                0xaa270000000cfff3,
                0x53cc0032fc34000a,
                0x478fe97a6b0a807f,
                0xb1d37ebee6ba24d7,
                0x8ec9733bbf78ab2f,
                0x9d645513d83de7e,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x6631000000105545,
                0x211400400eec000d,
                0x3fa7af30c820e316,
                0xc52a8b8d6387695d,
                0x9fb4e61d1e83eac5,
                0x5cb922afe84dc77,
            ]),
            c1: Fp::from_raw_unchecked([
                0x223b00000013aa97,
                0xee5c004d21a40010,
                0x37bf74e7253745ac,
                0xd881985be054ade3,
                0xb0a058fe7d8f2a5b,
                0x1c0df04bf85da70,
            ]),
        },
    };
    let c_sqrt = Fp6 {
        c0: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xbc5c83c79ee17378,
                0x6234c76e1e43427d,
                0xa967a76ded98934,
                0x60530cb49f3aa701,
                0xf1e78d8b238ce13b,
                0xcae66f9d906cc2,
            ]),
            c1: Fp::from_raw_unchecked([
                0x8e0b93ad5a9e2ad8,
                0x9f651961fde14bf2,
                0x4c1dbb672da9e549,
                0x6a9dd580ee524230,
                0x37f847eccc026,
                0x8759709a578b0d,
            ]),
        },
        c1: Fp2 {
            c0: Fp::from_raw_unchecked([
                0x1df7771f87b25d2d,
                0xce9d90f1fb56fe78,
                0xea74bda2cc72e5ea,
                0xf240542d5067f34e,
                0x5c127ed5f9d549c6,
                0x4b40109ac4a835a,
            ]),
            c1: Fp::from_raw_unchecked([
                0x280644f936de9b22,
                0xc66d88e8b24bcc50,
                0x59c13da5b138eb11,
                0x58eb4797886a4ad5,
                0x906577dcb6d18661,
                0x12b4501b3e3c9f3a,
            ]),
        },
        c2: Fp2 {
            c0: Fp::from_raw_unchecked([
                0xccbcf4677c99dfcb,
                0x8001c4f4626cc646,
                0x47d3f89c286446a9,
                0x1c85adb35001a959,
                0x933daef463a2592c,
                0x2763061b8787ca0,
            ]),
            c1: Fp::from_raw_unchecked([
                0xdcb4c1ccf25dcf8e,
                0xf1a4f384c2a0a4ae,
                0x3e20636334c0d7d1,
                0xcb6d42fd5a06e476,
                0x3eff57d6357d7d40,
                0x1528dc22578f54dd,
            ]),
        },
    };

    assert_eq!(c_sqrt * c_sqrt, c);
    assert_eq!(c.sqrt().unwrap().square(), c);
    assert_eq!(c.sqrt().unwrap(), c_sqrt);
}
