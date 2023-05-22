use core::convert::Infallible;

use dusk_bytes::{HexDebug, Serializable};
use subtle::ConditionallySelectable;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

/// Wrapper for a [`subtle::Choice`]
#[derive(Copy, Clone, HexDebug)]
#[cfg_attr(feature = "rkyv-impl", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv-impl", archive_attr(derive(CheckBytes)))]
pub struct Choice(u8);

impl Choice {
    pub fn unwrap_u8(&self) -> u8 {
        self.0
    }
}

impl ConditionallySelectable for Choice {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        Self(u8::conditional_select(&a.0, &b.0, choice))
    }
}

impl Serializable<1> for Choice {
    type Error = Infallible;

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self(buf[0]))
    }

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        [self.0; Self::SIZE]
    }
}

impl From<u8> for Choice {
    fn from(int: u8) -> Self {
        Self(int)
    }
}

impl From<Choice> for u8 {
    fn from(c: Choice) -> Self {
        c.0
    }
}

impl From<subtle::Choice> for Choice {
    fn from(c: subtle::Choice) -> Self {
        Self(c.unwrap_u8())
    }
}

impl From<Choice> for subtle::Choice {
    fn from(c: Choice) -> Self {
        subtle::Choice::from(c.0)
    }
}

impl From<Choice> for bool {
    fn from(c: Choice) -> Self {
        subtle::Choice::from(c.0).into()
    }
}
