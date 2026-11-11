//! Fixed-exponent addition chains for field arithmetic.

#[cfg(feature = "groups")]
#[macro_use]
mod p_minus3_over4;

#[cfg(feature = "groups")]
pub(crate) mod fp;
#[cfg(feature = "groups")]
pub(crate) mod fp2;
pub(crate) mod scalar;
