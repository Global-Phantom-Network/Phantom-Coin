// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing
)]

use core::fmt;
use std::io::{Read, Write};

#[derive(Debug)]
pub enum CodecError {
    Truncated,
    InvalidTag(u8),
    InvalidLength(usize),
    Io(std::io::Error),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated input"),
            Self::InvalidTag(t) => write!(f, "invalid tag: {t}"),
            Self::InvalidLength(n) => write!(f, "invalid length: {n}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for CodecError {}
impl From<std::io::Error> for CodecError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub trait Encodable {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError>;
    fn encoded_len(&self) -> usize;
}

pub trait Decodable: Sized {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError>;
}

// Varint (u64) - little endian base-128
pub fn write_varu64<W: Write>(w: &mut W, mut v: u64) -> Result<(), CodecError> {
    let mut buf = [0u8; 10];
    let mut i = 0usize;
    while v >= 0x80 {
        if let Some(slot) = buf.get_mut(i) {
            *slot = (v as u8) | 0x80;
        } else {
            return Err(CodecError::InvalidLength(i));
        }
        v >>= 7;
        i += 1;
    }
    if let Some(slot) = buf.get_mut(i) {
        *slot = v as u8;
    } else {
        return Err(CodecError::InvalidLength(i));
    }
    i += 1;
    let to_write = buf.get(..i).ok_or(CodecError::InvalidLength(i))?;
    w.write_all(to_write).map_err(CodecError::Io)
}

pub fn read_varu64<R: Read>(r: &mut R) -> Result<u64, CodecError> {
    let mut x: u64 = 0;
    let mut s = 0u32;
    for _ in 0..10 {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        let [byte] = b;
        if (byte & 0x80) != 0 {
            x |= ((byte & 0x7f) as u64) << s;
            s += 7;
        } else {
            x |= (byte as u64) << s;
            return Ok(x);
        }
    }
    Err(CodecError::InvalidLength(0))
}

// Implementations for primitives
impl Encodable for u8 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        w.write_all(&[*self]).map_err(CodecError::Io)
    }
    fn encoded_len(&self) -> usize {
        1
    }
}
impl Decodable for u8 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        let [byte] = b;
        Ok(byte)
    }
}

impl Encodable for bool {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        (*self as u8).encode(w)
    }
    fn encoded_len(&self) -> usize {
        1
    }
}
impl Decodable for bool {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        Ok(u8::decode(r)? != 0)
    }
}

impl Encodable for u16 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        w.write_all(&self.to_le_bytes()).map_err(CodecError::Io)
    }
    fn encoded_len(&self) -> usize {
        2
    }
}
impl Decodable for u16 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let mut b = [0u8; 2];
        r.read_exact(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }
}

impl Encodable for u32 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        w.write_all(&self.to_le_bytes()).map_err(CodecError::Io)
    }
    fn encoded_len(&self) -> usize {
        4
    }
}
impl Decodable for u32 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let mut b = [0u8; 4];
        r.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
}

impl Encodable for u64 {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        write_varu64(w, *self)
    }
    fn encoded_len(&self) -> usize {
        let mut v = *self;
        let mut i = 1;
        while v >= 0x80 {
            v >>= 7;
            i += 1
        }
        i
    }
}
impl Decodable for u64 {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        read_varu64(r)
    }
}

impl Encodable for [u8; 32] {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        w.write_all(self).map_err(CodecError::Io)
    }
    fn encoded_len(&self) -> usize {
        32
    }
}
impl Decodable for [u8; 32] {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let mut b = [0u8; 32];
        r.read_exact(&mut b)?;
        Ok(b)
    }
}

impl<T: Encodable> Encodable for Vec<T> {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), CodecError> {
        write_varu64(w, self.len() as u64)?;
        for item in self {
            item.encode(w)?;
        }
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        let mut v = self.len() as u64;
        let mut i = 1;
        while v >= 0x80 {
            v >>= 7;
            i += 1
        }
        self.iter().fold(i, |acc, it| acc + it.encoded_len())
    }
}
impl<T: Decodable> Decodable for Vec<T> {
    fn decode<R: Read>(r: &mut R) -> Result<Self, CodecError> {
        let len = read_varu64(r)? as usize;
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push(T::decode(r)?);
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn var_roundtrip() {
        let nums = [
            0u64,
            1,
            127,
            128,
            255,
            16384,
            u32::MAX as u64,
            u64::MAX >> 1,
        ];
        for &n in &nums {
            let mut buf = Vec::new();
            write_varu64(&mut buf, n).unwrap();
            let mut slice = &buf[..];
            let got = read_varu64(&mut slice).unwrap();
            assert_eq!(n, got);
        }
    }
}
