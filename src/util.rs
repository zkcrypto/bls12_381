/// Compute a + b + carry, returning the result and the new carry over.
#[inline(always)]
pub const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a - (b + borrow), returning the result and the new borrow.
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a + (b * c) + carry, returning the result and the new carry over.
#[inline(always)]
pub const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
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

macro_rules! impl_pippenger_sum_of_products {
    () => {
        /// Use pippenger multi-exponentiation method to compute
        /// the sum of multiple points raise to scalars.
        /// This uses a fixed window of 4 to be constant time
        #[cfg(feature = "alloc")]
        pub fn sum_of_products(points: &[Self], scalars: &[Scalar]) -> Self {
            use alloc::vec::Vec;

            let ss: Vec<Scalar> = scalars
                .iter()
                .map(|s| Scalar::montgomery_reduce(s.0[0], s.0[1], s.0[2], s.0[3], 0, 0, 0, 0))
                .collect();
            Self::sum_of_products_pippenger(points, ss.as_slice())
        }

        /// Use pippenger multi-exponentiation method to compute
        /// the sum of multiple points raise to scalars.
        /// This uses a fixed window of 4 to be constant time
        /// The scalars are used as place holders for temporary computations
        pub fn sum_of_products_in_place(points: &[Self], scalars: &mut [Scalar]) -> Self {
            // Scalars are in montgomery form, hack them in place to be temporarily
            // in canonical form, do the computation, then switch them back
            for i in 0..scalars.len() {
                // Turn into canonical form by computing (a.R) / R = a
                scalars[i] = Scalar::montgomery_reduce(
                    scalars[i].0[0],
                    scalars[i].0[1],
                    scalars[i].0[2],
                    scalars[i].0[3],
                    0,
                    0,
                    0,
                    0,
                );
            }

            let res = Self::sum_of_products_pippenger(points, scalars);
            for i in 0..scalars.len() {
                scalars[i] = Scalar::from_raw(scalars[i].0);
            }
            res
        }

        /// Compute pippenger multi-exponentiation.
        /// Pippenger relies on scalars in canonical form
        /// This uses a fixed window of 4 to be constant time
        fn sum_of_products_pippenger(points: &[Self], scalars: &[Scalar]) -> Self {
            const WINDOW: usize = 4;
            const NUM_BUCKETS: usize = 1 << WINDOW;
            const EDGE: usize = WINDOW - 1;
            const MASK: u64 = (NUM_BUCKETS - 1) as u64;

            let num_components = core::cmp::min(points.len(), scalars.len());
            let mut buckets = [Self::identity(); NUM_BUCKETS];
            let mut res = Self::identity();
            let mut num_doubles = 0;
            let mut bit_sequence_index = 255usize; // point to top bit we need to process

            loop {
                for _ in 0..num_doubles {
                    res = res.double();
                }

                let mut max_bucket = 0;
                let word_index = bit_sequence_index >> 6; // divide by 64 to find word_index
                let bit_index = bit_sequence_index & 63; // mod by 64 to find bit_index

                if bit_index < EDGE {
                    // we are on the edge of a word; have to look at the previous word, if it exists
                    if word_index == 0 {
                        // there is no word before
                        let smaller_mask = ((1 << (bit_index + 1)) - 1) as u64;
                        for i in 0..num_components {
                            let bucket_index: usize =
                                (scalars[i].0[word_index] & smaller_mask) as usize;
                            if bucket_index > 0 {
                                buckets[bucket_index] += points[i];
                                if bucket_index > max_bucket {
                                    max_bucket = bucket_index;
                                }
                            }
                        }
                    } else {
                        // there is a word before
                        let high_order_mask = ((1 << (bit_index + 1)) - 1) as u64;
                        let high_order_shift = EDGE - bit_index;
                        let low_order_mask = ((1 << high_order_shift) - 1) as u64;
                        let low_order_shift = 64 - high_order_shift;
                        let prev_word_index = word_index - 1;
                        for i in 0..num_components {
                            let mut bucket_index = ((scalars[i].0[word_index] & high_order_mask)
                                << high_order_shift)
                                as usize;
                            bucket_index |= ((scalars[i].0[prev_word_index] >> low_order_shift)
                                & low_order_mask) as usize;
                            if bucket_index > 0 {
                                buckets[bucket_index] += points[i];
                                if bucket_index > max_bucket {
                                    max_bucket = bucket_index;
                                }
                            }
                        }
                    }
                } else {
                    let shift = bit_index - EDGE;
                    for i in 0..num_components {
                        let bucket_index: usize =
                            ((scalars[i].0[word_index] >> shift) & MASK) as usize;
                        assert!(bit_sequence_index != 255 || scalars[i].0[3] >> 63 == 0);
                        if bucket_index > 0 {
                            buckets[bucket_index] += points[i];
                            if bucket_index > max_bucket {
                                max_bucket = bucket_index;
                            }
                        }
                    }
                }
                res += &buckets[max_bucket];
                for i in (1..max_bucket).rev() {
                    buckets[i] += buckets[i + 1];
                    res += buckets[i];
                    buckets[i + 1] = Self::identity();
                }
                buckets[1] = Self::identity();
                if bit_sequence_index < WINDOW {
                    break;
                }
                bit_sequence_index -= WINDOW;
                num_doubles = {
                    if bit_sequence_index < EDGE {
                        bit_sequence_index + 1
                    } else {
                        WINDOW
                    }
                };
            }
            res
        }
    };
}
