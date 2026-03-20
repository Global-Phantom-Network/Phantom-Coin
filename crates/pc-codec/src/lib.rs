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
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use core::fmt;
use std::io::{Read, Write};

#[derive(Debug)]
pub enum CodecError {
    Truncated,
    InvalidTag(u8),
    InvalidLength(usize),
    TrailingBytes(usize),
    Io(std::io::Error),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated input"),
            Self::InvalidTag(t) => write!(f, "invalid tag: {t}"),
            Self::InvalidLength(n) => write!(f, "invalid length: {n}"),
            Self::TrailingBytes(n) => write!(f, "trailing bytes: {n}"),
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

/// Decode from a byte slice and reject if there are trailing bytes (P1-1 hardening).
/// Dekodiere aus Byte-Slice und lehne ab wenn Trailing-Bytes vorhanden (P1-1 Härtung).
pub fn decode_exact<T: Decodable>(data: &[u8]) -> Result<T, CodecError> {
    let mut slice = data;
    let val = T::decode(&mut slice)?;
    if !slice.is_empty() {
        return Err(CodecError::TrailingBytes(slice.len()));
    }
    Ok(val)
}

const MAX_DECODE_VEC_BACKING_BYTES: usize = 8 * 1024 * 1024;
const MAX_DECODE_VEC_ZST_ELEMS: usize = 1024 * 1024;

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
    for i in 0..10usize {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        let [byte] = b;

        let lo = (byte & 0x7f) as u64;
        if i == 9 && lo > 1 {
            // Would overflow u64; canonical max uses at most one payload bit in byte 10.
            return Err(CodecError::InvalidLength(i + 1));
        }
        let shifted = lo.checked_shl(s).ok_or(CodecError::InvalidLength(i + 1))?;
        x |= shifted;

        if (byte & 0x80) == 0 {
            // Canonical varint: shortest possible encoding only.
            let mut min_len = 1usize;
            let mut tmp = x;
            while tmp >= 0x80 {
                tmp >>= 7;
                min_len += 1;
            }
            if min_len != i + 1 {
                return Err(CodecError::InvalidLength(i + 1));
            }
            return Ok(x);
        }
        s += 7;
    }
    Err(CodecError::InvalidLength(10))
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
        match u8::decode(r)? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(CodecError::InvalidTag(other)),
        }
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
        let len_u64 = read_varu64(r)?;
        let len: usize = usize::try_from(len_u64).map_err(|_| CodecError::InvalidLength(0))?;

        let elem_size = core::mem::size_of::<T>();
        if elem_size == 0 {
            if len > MAX_DECODE_VEC_ZST_ELEMS {
                return Err(CodecError::InvalidLength(len));
            }
        } else {
            let max_elems = MAX_DECODE_VEC_BACKING_BYTES / elem_size;
            if len > max_elems {
                return Err(CodecError::InvalidLength(len));
            }
        }

        let mut v = Vec::new();
        v.try_reserve_exact(len)
            .map_err(|_e| CodecError::InvalidLength(len))?;
        for _ in 0..len {
            v.push(T::decode(r)?);
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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

    #[test]
    fn var_truncated_errors() {
        // Zwei Bytes mit gesetztem Continue-Bit, dann Ende → sollte IO/Truncated-Error geben
        let data = [0x80u8, 0x80u8];
        let mut s = &data[..];
        let err = read_varu64(&mut s).unwrap_err();
        match err {
            CodecError::Io(_) => {}
            _ => panic!("expected Io error for truncated varint"),
        }
    }

    #[test]
    fn var_overlong_no_terminator_errors() {
        // 10 Bytes mit Continue-Bit (kein Terminator) → sollte InvalidLength(0) liefern
        let data = [0x80u8; 10];
        let mut s = &data[..];
        let err = read_varu64(&mut s).unwrap_err();
        match err {
            CodecError::InvalidLength(10) => {}
            _ => panic!("expected InvalidLength(10) for overlong varint without terminator"),
        }
    }

    #[test]
    fn var_overlong_non_canonical_zero_rejected() {
        // Canonical zero is [0x00], so [0x80, 0x00] is invalid.
        let data = [0x80u8, 0x00u8];
        let mut s = &data[..];
        let err = read_varu64(&mut s).unwrap_err();
        assert!(matches!(err, CodecError::InvalidLength(2)));
    }

    #[test]
    fn bool_decode_non_canonical_rejected() {
        for b in [2u8, 3u8, 0xFFu8] {
            let mut s = &[b][..];
            let err = bool::decode(&mut s).unwrap_err();
            assert!(matches!(err, CodecError::InvalidTag(v) if v == b));
        }
    }

    #[test]
    fn decode_array32_truncated() {
        // Nur 31 Bytes statt 32 → Truncated/Io Fehler
        let data = [0x11u8; 31];
        let mut s = &data[..];
        let err = <[u8; 32]>::decode(&mut s).unwrap_err();
        match err {
            CodecError::Io(_) => {}
            _ => panic!("expected Io error for truncated [u8;32]"),
        }
    }

    #[test]
    fn decode_vec_len_then_truncated_elements() {
        // Vec<u8> mit len=2 (02), aber nur 1 Element vorhanden → Truncated/Io Fehler
        let data = [0x02u8, 0xABu8];
        let mut s = &data[..];
        let err = <Vec<u8>>::decode(&mut s).unwrap_err();
        match err {
            CodecError::Io(_) => {}
            _ => panic!("expected Io error for truncated Vec elements"),
        }
    }

    proptest! {
        #[test]
        fn prop_var_roundtrip(n in any::<u64>()) {
            let mut buf = Vec::new();
            write_varu64(&mut buf, n).unwrap();
            let mut s = &buf[..];
            let got = read_varu64(&mut s).unwrap();
            prop_assert_eq!(n, got);
        }

        #[test]
        fn prop_vec_u8_roundtrip(v in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let mut buf = Vec::new();
            v.encode(&mut buf).unwrap();
            let mut s = &buf[..];
            let got = <Vec<u8>>::decode(&mut s).unwrap();
            prop_assert_eq!(v, got);
        }

        #[test]
        fn prop_vec_array32_roundtrip(v in proptest::collection::vec(any::<[u8;32]>(), 0..128)) {
            let mut buf = Vec::new();
            v.encode(&mut buf).unwrap();
            let mut s = &buf[..];
            let got = <Vec<[u8;32]>>::decode(&mut s).unwrap();
            prop_assert_eq!(v, got);
        }

        #[test]
        fn prop_nested_vec_roundtrip(v in proptest::collection::vec(proptest::collection::vec(any::<[u8;32]>(), 0..32), 0..16)) {
            let mut buf = Vec::new();
            v.encode(&mut buf).unwrap();
            let mut s = &buf[..];
            let got = <Vec<Vec<[u8;32]>>>::decode(&mut s).unwrap();
            prop_assert_eq!(v, got);
        }
    }

    #[test]
    fn decode_exact_rejects_trailing_bytes_p1_1() {
        // P1-1: decode_exact must reject data with trailing bytes.
        // P1-1: decode_exact muss Daten mit Trailing-Bytes ablehnen.
        let mut buf = Vec::new();
        42u64.encode(&mut buf).unwrap();
        buf.push(0xFF); // trailing byte
        let err = decode_exact::<u64>(&buf).unwrap_err();
        match err {
            CodecError::TrailingBytes(1) => {}
            _ => panic!("expected TrailingBytes(1), got {:?}", err),
        }
    }

    #[test]
    fn decode_exact_accepts_exact_data_p1_1() {
        // P1-1: decode_exact must accept data with no trailing bytes.
        // P1-1: decode_exact muss Daten ohne Trailing-Bytes akzeptieren.
        let mut buf = Vec::new();
        42u64.encode(&mut buf).unwrap();
        let val = decode_exact::<u64>(&buf).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn decode_exact_array32_trailing_p1_1() {
        // P1-1: [u8; 32] with trailing byte must fail.
        // P1-1: [u8; 32] mit Trailing-Byte muss fehlschlagen.
        let buf = [0x11u8; 33];
        let err = decode_exact::<[u8; 32]>(&buf).unwrap_err();
        match err {
            CodecError::TrailingBytes(1) => {}
            _ => panic!("expected TrailingBytes(1), got {:?}", err),
        }
    }

    #[test]
    fn fuzz_varint_absurd_large_len_rejected() {
        // Fuzz: Absurd große Länge muss abgelehnt werden.
        // Encode a huge length (u64::MAX) - should fail on allocation.
        let mut buf = Vec::new();
        write_varu64(&mut buf, u64::MAX).unwrap();
        let mut s = &buf[..];
        let len = read_varu64(&mut s).unwrap();
        assert_eq!(len, u64::MAX);
        // Now try to decode a Vec with that length - must fail.
        let mut data = Vec::new();
        write_varu64(&mut data, u64::MAX).unwrap();
        let mut s2 = &data[..];
        let err = <Vec<u8>>::decode(&mut s2).unwrap_err();
        assert!(matches!(err, CodecError::InvalidLength(_)));
    }

    #[test]
    fn fuzz_varint_large_but_within_limit() {
        // Fuzz: Länge knapp unter MAX_DECODE_VEC_BACKING_BYTES sollte InvalidLength geben.
        // 8MB + 1 elements should fail.
        let bad_len = (8 * 1024 * 1024 + 1) as u64;
        let mut data = Vec::new();
        write_varu64(&mut data, bad_len).unwrap();
        let mut s = &data[..];
        let err = <Vec<u8>>::decode(&mut s).unwrap_err();
        assert!(matches!(err, CodecError::InvalidLength(_)));
    }

    #[test]
    fn fuzz_vec_claimed_len_exceeds_data() {
        // Fuzz: Vec behauptet 1000 Elemente aber hat nur 5 Bytes.
        let mut data = Vec::new();
        write_varu64(&mut data, 1000).unwrap();
        data.extend_from_slice(&[1, 2, 3, 4, 5]);
        let mut s = &data[..];
        let err = <Vec<u8>>::decode(&mut s).unwrap_err();
        assert!(matches!(err, CodecError::Io(_)));
    }

    #[test]
    fn fuzz_nested_vec_depth_bomb() {
        // Fuzz: Tief verschachtelte Vecs sollten nicht zum Stack-Overflow führen.
        // Vec<Vec<Vec<u8>>> mit je 1 Element.
        let mut data = Vec::new();
        write_varu64(&mut data, 1).unwrap(); // outer len=1
        write_varu64(&mut data, 1).unwrap(); // mid len=1
        write_varu64(&mut data, 1).unwrap(); // inner len=1
        data.push(0xAB);
        let mut s = &data[..];
        let got: Vec<Vec<Vec<u8>>> = Decodable::decode(&mut s).unwrap();
        assert_eq!(got, vec![vec![vec![0xAB]]]);
    }
}
