//! Multiscalar multiplication implementation using pippenger algorithm.
use crate::{
    g1::{G1Affine, G1Projective},
    scalar::Scalar,
};
use byteorder;

#[cfg(feature = "std")]
/// Performs multiscalar multiplication reliying on Pippenger's algorithm.
/// This method was taken from `curve25519-dalek` and was originally made by
/// Oleg Andreev <oleganza@gmail.com>.
pub fn pippenger<P, I>(points: P, scalars: I) -> G1Projective
where
    P: Iterator<Item = G1Projective>,
    I: Iterator<Item = Scalar>,
{
    let size = scalars.size_hint().0;

    // Digit width in bits. As digit width grows,
    // number of point additions goes down, but amount of
    // buckets and bucket additions grows exponentially.
    let w = if size < 500 {
        6
    } else if size < 800 {
        7
    } else {
        8
    };

    let max_digit: usize = 1 << w;
    let digits_count: usize = to_radix_2w_size_hint(w);
    let buckets_count: usize = max_digit / 2; // digits are signed+centered hence 2^w/2, excluding 0-th bucket

    // Collect optimized scalars and points in buffers for repeated access
    // (scanning the whole set per digit position).
    let scalars = scalars.map(|s| to_radix_2w(&s, w));
    let scalars_points = scalars.zip(points).collect::<Vec<_>>();

    // Prepare 2^w/2 buckets.
    // buckets[i] corresponds to a multiplication factor (i+1).
    let mut buckets: Vec<_> = (0..buckets_count)
        .map(|_| G1Projective::identity())
        .collect();

    let mut columns = (0..digits_count).rev().map(|digit_index| {
        // Clear the buckets when processing another digit.
        for i in 0..buckets_count {
            buckets[i] = G1Projective::identity();
        }

        // Iterate over pairs of (point, scalar)
        // and add/sub the point to the corresponding bucket.
        // Note: if we add support for precomputed lookup tables,
        // we'll be adding/subtracting point premultiplied by `digits[i]` to buckets[0].
        for (digits, pt) in scalars_points.iter() {
            // Widen digit so that we don't run into edge cases when w=8.
            let digit = digits[digit_index] as i16;
            if digit > 0 {
                let b = (digit - 1) as usize;
                buckets[b] = buckets[b] + pt;
            } else if digit < 0 {
                let b = (-digit - 1) as usize;
                buckets[b] = buckets[b] - pt;
            }
        }

        // Add the buckets applying the multiplication factor to each bucket.
        // The most efficient way to do that is to have a single sum with two running sums:
        // an intermediate sum from last bucket to the first, and a sum of intermediate sums.
        //
        // For example, to add buckets 1*A, 2*B, 3*C we need to add these points:
        //   C
        //   C B
        //   C B A   Sum = C + (C+B) + (C+B+A)
        let mut buckets_intermediate_sum = buckets[buckets_count - 1];
        let mut buckets_sum = buckets[buckets_count - 1];
        for i in (0..(buckets_count - 1)).rev() {
            buckets_intermediate_sum += buckets[i];
            buckets_sum += buckets_intermediate_sum;
        }

        buckets_sum
    });

    // Take the high column as an initial value to avoid wasting time doubling the identity element in `fold()`.
    // `unwrap()` always succeeds because we know we have more than zero digits.
    let hi_column = columns.next().unwrap();

    columns.fold(hi_column, |total, p| mul_by_pow_2(&total, w as u32) + p)
}

/// Compute \\([2\^k] P \\) by successive doublings. Requires \\( k > 0 \\).
pub(crate) fn mul_by_pow_2(point: &G1Projective, k: u32) -> G1Projective {
    debug_assert!(k > 0);
    let mut r: G1Projective;
    let mut s = point;
    for _ in 0..(k - 1) {
        r = s.double();
        s = &r;
    }
    // Unroll last iteration so we can go directly to_extended()
    s.double()
}

/// Returns a size hint indicating how many entries of the return
/// value of `to_radix_2w` are nonzero.
fn to_radix_2w_size_hint(w: usize) -> usize {
    debug_assert!(w >= 6);
    debug_assert!(w <= 8);

    let digits_count = match w {
        6 => (256 + w - 1) / w as usize,
        7 => (256 + w - 1) / w as usize,
        // See comment in to_radix_2w on handling the terminal carry.
        8 => (256 + w - 1) / w + 1 as usize,
        _ => panic!("invalid radix parameter"),
    };

    debug_assert!(digits_count <= 43);
    digits_count
}

fn to_radix_2w(scalar: &Scalar, w: usize) -> [i8; 43] {
    debug_assert!(w >= 6);
    debug_assert!(w <= 8);

    use byteorder::{ByteOrder, LittleEndian};

    // Scalar formatted as four `u64`s with carry bit packed into the highest bit.
    let mut scalar64x4 = [0u64; 4];
    LittleEndian::read_u64_into(&scalar.to_bytes(), &mut scalar64x4[0..4]);

    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let mut digits = [0i8; 43];
    let digits_count = (256 + w - 1) / w as usize;
    for i in 0..digits_count {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;

        // Read the bits from the scalar
        let bit_buf: u64;
        if bit_idx < 64 - w || u64_idx == 3 {
            // This window's bits are contained in a single u64,
            // or it's the last u64 anyway.
            bit_buf = scalar64x4[u64_idx] >> bit_idx;
        } else {
            // Combine the current u64's bits with the bits from the next u64
            bit_buf =
                (scalar64x4[u64_idx] >> bit_idx) | (scalar64x4[1 + u64_idx] << (64 - bit_idx));
        }

        // Read the actual coefficient value from the window
        let coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + (radix / 2) as u64) >> w;
        digits[i] = ((coef as i64) - (carry << w) as i64) as i8;
    }

    // When w < 8, we can fold the final carry onto the last digit d,
    // because d < 2^w/2 so d + carry*2^w = d + 1*2^w < 2^(w+1) < 2^8.
    //
    // When w = 8, we can't fit carry*2^w into an i8.  This should
    // not happen anyways, because the final carry will be 0 for
    // reduced scalars, but the Scalar invariant allows 255-bit scalars.
    // To handle this, we expand the size_hint by 1 when w=8,
    // and accumulate the final carry onto another digit.
    match w {
        8 => digits[digits_count] += carry as i8,
        _ => digits[digits_count - 1] += (carry << w) as i8,
    }

    digits
}

#[cfg(feature = "std")]
/// Performs a Variable Base Multiscalar Multiplication.
pub fn msm_variable_base(points: &[G1Affine], scalars: &[Scalar]) -> G1Projective {
    use rayon::prelude::*;

    let c = if scalars.len() < 32 {
        3
    } else {
        ln_without_floats(scalars.len()) + 2
    };

    let num_bits = 255usize;
    let fr_one = Scalar::one();

    let zero = G1Projective::identity();
    let window_starts: Vec<_> = (0..num_bits).step_by(c).collect();

    let window_starts_iter = window_starts.into_par_iter();

    // Each window is of size `c`.
    // We divide up the bits 0..num_bits into windows of size `c`, and
    // in parallel process each such window.
    let window_sums: Vec<_> = window_starts_iter
        .map(|w_start| {
            let mut res = zero;
            // We don't need the "zero" bucket, so we only have 2^c - 1 buckets
            let mut buckets = vec![zero; (1 << c) - 1];
            scalars
                .iter()
                .zip(points)
                .filter(|(s, _)| !(*s == &Scalar::zero()))
                .for_each(|(&scalar, base)| {
                    if scalar == fr_one {
                        // We only process unit scalars once in the first window.
                        if w_start == 0 {
                            res = res.add_mixed(base);
                        }
                    } else {
                        let mut scalar = scalar.reduce();

                        // We right-shift by w_start, thus getting rid of the
                        // lower bits.
                        scalar.divn(w_start as u32);

                        // We mod the remaining bits by the window size.
                        let scalar = scalar.0[0] % (1 << c);

                        // If the scalar is non-zero, we update the corresponding
                        // bucket.
                        // (Recall that `buckets` doesn't have a zero bucket.)
                        if scalar != 0 {
                            buckets[(scalar - 1) as usize] =
                                buckets[(scalar - 1) as usize].add_mixed(base);
                        }
                    }
                });

            let mut running_sum = G1Projective::identity();
            for b in buckets.into_iter().rev() {
                running_sum = running_sum + b;
                res += &running_sum;
            }

            res
        })
        .collect();

    // We store the sum for the lowest window.
    let lowest = *window_sums.first().unwrap();
    // We're traversing windows from high to low.
    window_sums[1..]
        .iter()
        .rev()
        .fold(zero, |mut total, sum_i| {
            total += sum_i;
            for _ in 0..c {
                total = total.double();
            }
            total
        })
        + lowest
}

fn ln_without_floats(a: usize) -> usize {
    // log2(a) * ln(2)
    (log2(a) * 69 / 100) as usize
}
fn log2(x: usize) -> u32 {
    if x <= 1 {
        return 0;
    }

    let n = x.leading_zeros();
    core::mem::size_of::<usize>() as u32 * 8 - n
}

mod tests {
    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn pippenger_test() {
        // Reuse points across different tests
        let mut n = 512;
        let x = Scalar::from(2128506u64).invert().unwrap();
        let y = Scalar::from(4443282u64).invert().unwrap();
        let points = (0..n)
            .map(|i| G1Projective::generator() * Scalar::from(1 + i as u64))
            .collect::<Vec<_>>();
        let scalars = (0..n)
            .map(|i| x + (Scalar::from(i as u64) * y))
            .collect::<Vec<_>>(); // fast way to make ~random but deterministic scalars
        let premultiplied: Vec<G1Projective> = scalars
            .iter()
            .zip(points.iter())
            .map(|(sc, pt)| pt * sc)
            .collect();
        while n > 0 {
            let scalars = &scalars[0..n];
            let points = &points[0..n];
            let control: G1Projective = premultiplied[0..n].iter().sum();
            let subject = pippenger(
                points.to_owned().into_iter(),
                scalars.to_owned().into_iter(),
            );
            assert_eq!(subject, control);
            n = n / 2;
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn msm_variable_base_test() {
        let points = vec![G1Affine::generator()];
        let scalars = vec![Scalar::from(100u64)];
        let premultiplied = G1Projective::generator() * Scalar::from(100u64);
        let subject = msm_variable_base(&points, &scalars);
        assert_eq!(subject, premultiplied);
    }
}
