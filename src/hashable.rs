use crate::g1::{G1Affine, G1Projective};
use crate::g2::{G2Affine, G2Projective};
use sha2::{Digest, Sha512};

// Hash a message using Sha512, and then return the first N bytes
// used to map to a curve point.
macro_rules! make_hash {
    ($message:ident, $i:ident, $array_size:literal) => {{
        let mut result = [0u8; $array_size];

        // The incrementing nonce value until we produce a valid point
        let i_data = $i.to_le_bytes();

        // We build the compressed point in chunks of 64 bytes each
        // G1 requires a single round
        // G2 requires double rounds
        // Add a j value for each chunk:
        //   [message][i][j=0] | [message][i][j=1] ...
        const HASH_SIZE: usize = 64;
        let mut j = 0;
        while j * HASH_SIZE < $array_size {
            let j_data = j.to_le_bytes();

            // Hash the data
            let mut hasher = Sha512::new();
            hasher.input($message);
            hasher.input(&i_data);
            hasher.input(&j_data);
            let hash_result = hasher.result();

            // Calculate start and end indexes
            let start = j * HASH_SIZE;
            let end = if start + HASH_SIZE > $array_size {
                $array_size
            } else {
                start + HASH_SIZE
            };

            // Copy data from GenericArray to Rust fixed size array result
            result.copy_from_slice(&hash_result[start..end]);

            j += 1;
        }

        result
    }};
}

// For now we define this trait for G1Affine and G2Affine, but later the code
// from the classes themselves should be refactored into a common trait that enables
// code reuse
trait AffinePoint {
    // Point is on the curve and doesn't have torsion
    fn is_valid(&self) -> bool;

    // Clear cofactor z value
    fn clear_cofactor(&self) -> Self;
}

impl AffinePoint for G1Affine {
    fn is_valid(&self) -> bool {
        bool::from(self.is_on_curve()) && bool::from(self.is_torsion_free())
    }

    fn clear_cofactor(&self) -> Self {
        let projective_point = G1Projective::from(self).clear_cofactor();
        Self::from(projective_point)
    }
}

impl AffinePoint for G2Affine {
    fn is_valid(&self) -> bool {
        bool::from(self.is_on_curve()) && bool::from(self.is_torsion_free())
    }

    fn clear_cofactor(&self) -> Self {
        let projective_point = G2Projective::from(self).clear_cofactor();
        Self::from(projective_point)
    }
}

pub trait HashableGenerator {
    /// Take a message slice and hash to a point on the curve.
    /// Uses an incrementing nonce to keep iterating hashing the message,
    /// until it obtains a valid point on the curve. Naive implementation.
    fn hash_to_point(message: &[u8]) -> Self;
}

// Extend G1 point with a hash_to_point() method.
// The code for G2 and G2 is the same since we need to refactor the classes to
// put the common functions in a shared trait.
// For now we just define 2 separate implementations as a first step.
impl HashableGenerator for G1Affine {
    fn hash_to_point(message: &[u8]) -> Self {
        // Loop until we obtain a valid point.
        for i in 0u32.. {
            let hash = make_hash!(message, i, 48);

            let point = {
                // We cannot make generic since G1 uses 48 bytes, whereas G2 uses 96 bytes
                // Possible solution is to add methods to G1/G2Affine taking a slice rather than
                // an array, with an assert to check the length is correct.
                let point_optional = Self::from_compressed_unchecked(&hash);
                if point_optional.is_none().unwrap_u8() == 1 {
                    continue;
                }
                let affine_point = point_optional.unwrap();
                affine_point.clear_cofactor()
            };

            assert_eq!(point.is_valid(), true);

            return point;
        }
        unreachable!();
    }
}

// Add conversions for the projective version of G1
impl HashableGenerator for G1Projective {
    fn hash_to_point(message: &[u8]) -> Self {
        Self::from(G1Affine::hash_to_point(&message))
    }
}

impl HashableGenerator for G2Affine {
    fn hash_to_point(message: &[u8]) -> Self {
        // Loop until we obtain a valid point.
        for i in 0u32.. {
            let hash = make_hash!(message, i, 96);

            let point = {
                let point_optional = Self::from_compressed_unchecked(&hash);
                if point_optional.is_none().unwrap_u8() == 1 {
                    continue;
                }
                let affine_point = point_optional.unwrap();
                affine_point.clear_cofactor()
            };

            assert_eq!(point.is_valid(), true);

            return point;
        }
        unreachable!();
    }
}

// Add conversions for the projective version of G2
impl HashableGenerator for G2Projective {
    fn hash_to_point(message: &[u8]) -> Self {
        Self::from(G2Affine::hash_to_point(&message))
    }
}

#[test]
fn test_hash_to_point_g1affine() {
    // TODO
}
