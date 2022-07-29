use serde::{
    de::{Error as DError, Unexpected, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt::{self, Formatter};

/// The most bytes a uint can take
pub const UINT_MAX_LEN: usize = 10;

/// Implements zig-zag encoding for efficiently
/// representing integers as bytes
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Uint(pub u64);

macro_rules! impl_from {
    ($($ty:ty),+) => {
        $(
        impl From<$ty> for Uint {
            fn from(v: $ty) -> Self {
                Self(v as u64)
            }
        }
        )+
    };
}

impl From<u64> for Uint {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl_from!(u8, u16, u32, usize, i8, i16, i32, i64, isize);

impl TryFrom<&[u8]> for Uint {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut x = 0u64;
        let mut i = 0;
        let mut s = 0;

        while i < UINT_MAX_LEN {
            if i > value.len() {
                return Err(String::from("invalid byte sequence"));
            }
            if value[i] < 0x80 {
                return Ok(Self(x | ((value[i] as u64) << s)));
            }

            x |= ((value[i] & 0x7F) as u64) << s;
            s += 7;
            i += 1;
        }
        return Err(String::from("invalid byte sequence"));
    }
}

impl From<Uint> for Vec<u8> {
    fn from(u: Uint) -> Self {
        u.to_bytes()
    }
}

impl Serialize for Uint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'a> Deserialize<'a> for Uint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct UintVisitor;

        impl<'a> Visitor<'a> for UintVisitor {
            type Value = Uint;

            fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "a byte sequence")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: DError,
            {
                Uint::try_from(v).map_err(|_| DError::invalid_type(Unexpected::Bytes(v), &self))
            }
        }

        deserializer.deserialize_bytes(UintVisitor)
    }
}

impl Uint {
    /// Convert to a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = [0u8; UINT_MAX_LEN];
        let mut i = 0;
        let mut x = self.0;
        while x >= 0x80 {
            buf[i] = (x as u8) | 0x80;
            x >>= 7;
            i += 1;
        }
        buf[i] = x as u8;
        i += 1;
        let mut res = Vec::with_capacity(i);
        res.copy_from_slice(&buf[..i]);
        res
    }

    /// Calculate the number of bytes that would be read
    /// or None if `value` cannot an interpreted as a Uint
    pub fn peek(value: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < UINT_MAX_LEN {
            if i > value.len() {
                return None;
            }
            if value[i] < 0x80 {
                return Some(i + 1);
            }
            i += 1;
        }
        None
    }
}
