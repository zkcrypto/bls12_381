// Scalar recoding for group multiplication.

/// Recodes the low 255 bits of a little-endian scalar into 161 little-endian
/// ternary digits. The high bit is ignored, as in the existing group multiply
/// implementations.
pub(crate) fn to_radix_3(by: &[u8; 32]) -> [u8; 161] {
    let mut limbs = [0u32; 8];
    for i in 0..8 {
        limbs[i] = u32::from_le_bytes([by[4 * i], by[4 * i + 1], by[4 * i + 2], by[4 * i + 3]]);
    }
    limbs[7] &= 0x7fff_ffff;

    let mut digits = [0u8; 161];
    for digit in &mut digits {
        let mut remainder = 0u64;
        // Long division from the most significant limb to the least. The
        // dividend fits in 34 bits because the incoming remainder is < 3.
        for limb in limbs.iter_mut().rev() {
            let dividend = (remainder << 32) | u64::from(*limb);
            let quotient = dividend / 3;
            remainder = dividend - quotient * 3;
            *limb = quotient as u32;
        }
        *digit = remainder as u8;
    }
    digits
}

#[cfg(test)]
mod tests {
    use super::to_radix_3;
    use crate::Scalar;

    fn check_reconstruction(by: &[u8; 32]) -> [u8; 161] {
        let digits = to_radix_3(by);
        let mut reconstructed = [0u8; 32];
        for &digit in digits.iter().rev() {
            assert!(digit < 3);
            let mut carry = u16::from(digit);
            for byte in &mut reconstructed {
                let value = u16::from(*byte) * 3 + carry;
                *byte = value as u8;
                carry = value >> 8;
            }
            assert_eq!(carry, 0, "radix-3 reconstruction overflowed 256 bits");
        }
        let mut expected = *by;
        expected[31] &= 0x7f;
        assert_eq!(reconstructed, expected);
        digits
    }

    #[test]
    fn boundary_values() {
        check_reconstruction(&[0; 32]);
        check_reconstruction(&Scalar::one().to_bytes());
        check_reconstruction(&(-&Scalar::one()).to_bytes());
        check_reconstruction(&[0xff; 32]);

        let mut max_low_255 = [0xff; 32];
        max_low_255[31] = 0x7f;
        assert_eq!(to_radix_3(&max_low_255), to_radix_3(&[0xff; 32]));
        check_reconstruction(&max_low_255);

        let mut top_bit_only = [0; 32];
        top_bit_only[31] = 0x80;
        assert_eq!(to_radix_3(&top_bit_only), [0; 161]);
        check_reconstruction(&top_bit_only);
    }

    #[test]
    fn powers_of_three_and_neighbors() {
        let mut power = [0u8; 32];
        power[0] = 1;
        for exponent in 0..161 {
            let digits = check_reconstruction(&power);
            for (position, &digit) in digits.iter().enumerate() {
                assert_eq!(digit, u8::from(position == exponent));
            }

            let mut below = power;
            for byte in &mut below {
                let (value, borrow) = byte.overflowing_sub(1);
                *byte = value;
                if !borrow {
                    break;
                }
            }
            check_reconstruction(&below);

            let mut above = power;
            for byte in &mut above {
                let (value, carry) = byte.overflowing_add(1);
                *byte = value;
                if !carry {
                    break;
                }
            }
            check_reconstruction(&above);

            if exponent < 160 {
                let mut carry = 0u16;
                for byte in &mut power {
                    let value = u16::from(*byte) * 3 + carry;
                    *byte = value as u8;
                    carry = value >> 8;
                }
                assert_eq!(carry, 0);
            }
        }
    }

    #[test]
    fn deterministic_random_bytes() {
        let mut state = 0x8e83_96b3_fcb2_7a45u64;
        for _ in 0..256 {
            let mut by = [0u8; 32];
            for chunk in by.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            check_reconstruction(&by);
        }
    }
}
