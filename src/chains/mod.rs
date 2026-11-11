//! Fixed-exponent addition chains for field arithmetic.

#[cfg(feature = "experimental")]
#[macro_use]
mod p_minus3_over4;

#[cfg(feature = "experimental")]
pub(crate) mod fp;
#[cfg(feature = "experimental")]
pub(crate) mod fp2;
pub(crate) mod scalar;
