//! A CBOR (RFC 8949) codec, just enough for the COSE objects Bitwarden uses. Input comes from the server, so every
//! read is checked against the bytes left before anything is allocated, nesting is limited, and only definite-length
//! items without tags or floats are accepted, which is all Bitwarden's SDK produces.

use super::CryptoError;
use std::collections::HashSet;
use std::ops::Deref;
use zeroize::{Zeroize, Zeroizing};

const MAX_DEPTH: usize = 16;

/// A CBOR text, wiped on drop. Under the `testing` feature every live one is counted per thread, so a test can see
/// that nothing decoded outlives a scan (`testing::cbor_texts_alive`).
#[derive(Debug, PartialEq, Eq)]
pub struct CborText(Zeroizing<String>);

#[cfg(feature = "testing")]
thread_local!(static TEXTS_ALIVE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) });

/// How many `CborText`s this thread holds.
#[cfg(feature = "testing")]
pub(crate) fn texts_alive() -> usize {
    TEXTS_ALIVE.with(std::cell::Cell::get)
}

impl From<String> for CborText {
    fn from(text: String) -> Self {
        #[cfg(feature = "testing")]
        TEXTS_ALIVE.with(|n| n.set(n.get().saturating_add(1)));
        CborText(Zeroizing::new(text))
    }
}

impl Clone for CborText {
    fn clone(&self) -> Self {
        CborText::from(String::clone(&self.0))
    }
}

#[cfg(feature = "testing")]
impl Drop for CborText {
    fn drop(&mut self) {
        TEXTS_ALIVE.with(|n| n.set(n.get().saturating_sub(1)));
    }
}

impl Deref for CborText {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}

impl Zeroize for CborText {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Integer and text keys are kept apart, as CBOR does: `Uint(1)` is not `Text("1")`. `Nint(n)` is `-1 - n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cbor {
    Uint(u64),
    Nint(u64),
    Bytes(Zeroizing<Vec<u8>>),
    Text(CborText),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

impl Cbor {
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        Cbor::Bytes(Zeroizing::new(b.into()))
    }

    pub fn text(t: impl Into<String>) -> Self {
        Cbor::Text(CborText::from(t.into()))
    }

    /// What makes a map key unique: integers and texts only (labels, never secrets).
    fn identity(&self) -> Option<Vec<u8>> {
        match self {
            Cbor::Uint(n) => Some([&[0][..], &n.to_be_bytes()].concat()),
            Cbor::Nint(n) => Some([&[1][..], &n.to_be_bytes()].concat()),
            Cbor::Text(t) => Some([&[2][..], t.as_bytes()].concat()),
            _ => None,
        }
    }
}

impl Zeroize for Cbor {
    fn zeroize(&mut self) {
        match self {
            Cbor::Bytes(b) => b.zeroize(),
            Cbor::Text(t) => t.zeroize(),
            Cbor::Array(a) => a.iter_mut().for_each(Zeroize::zeroize),
            Cbor::Map(m) => m.iter_mut().for_each(|(k, v)| {
                k.zeroize();
                v.zeroize();
            }),
            Cbor::Uint(_) | Cbor::Nint(_) | Cbor::Bool(_) | Cbor::Null => {}
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CryptoError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(CryptoError::Malformed)?;
        self.0 = rest;
        Ok(head)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CryptoError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// The argument of a head byte: integers and lengths up to 2^64-1.
    fn argument(&mut self, info: u8) -> Result<u64, CryptoError> {
        let size = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(CryptoError::Malformed), // indefinite lengths and reserved values
        };
        Ok(self.take(size)?.iter().fold(0, |v, b| (v << 8) | u64::from(*b)))
    }

    fn length(&mut self, info: u8) -> Result<usize, CryptoError> {
        usize::try_from(self.argument(info)?).map_err(|_| CryptoError::Malformed)
    }

    /// An item count. Every element takes at least one byte, so a count beyond the bytes left is refused before
    /// anything is reserved.
    fn count(&mut self, info: u8) -> Result<usize, CryptoError> {
        let n = self.length(info)?;
        if n > self.0.len() {
            return Err(CryptoError::Malformed);
        }
        Ok(n)
    }
}

/// Decodes one CBOR item that must fill `bytes` exactly.
pub fn decode(bytes: &[u8]) -> Result<Cbor, CryptoError> {
    let mut r = Reader(bytes);
    let v = read(&mut r, 0)?;
    if !r.0.is_empty() {
        return Err(CryptoError::Malformed);
    }
    Ok(v)
}

fn read(r: &mut Reader, depth: usize) -> Result<Cbor, CryptoError> {
    if depth > MAX_DEPTH {
        return Err(CryptoError::Malformed);
    }
    let [head] = r.take_array::<1>()?;
    let (major, info) = (head >> 5, head & 0x1f);
    Ok(match major {
        0 => Cbor::Uint(r.argument(info)?),
        1 => Cbor::Nint(r.argument(info)?),
        2 => {
            let n = r.length(info)?;
            Cbor::bytes(r.take(n)?)
        }
        3 => {
            let n = r.length(info)?;
            Cbor::text(std::str::from_utf8(r.take(n)?).map_err(|_| CryptoError::Malformed)?)
        }
        4 => {
            let n = r.count(info)?;
            let mut out = Vec::new();
            for _ in 0..n {
                out.push(read(r, depth + 1)?);
            }
            Cbor::Array(out)
        }
        5 => {
            let n = r.count(info)?;
            let (mut out, mut seen) = (Vec::new(), HashSet::new());
            for _ in 0..n {
                let key = read(r, depth + 1)?;
                if !key.identity().is_some_and(|id| seen.insert(id)) {
                    return Err(CryptoError::Malformed);
                }
                out.push((key, read(r, depth + 1)?));
            }
            Cbor::Map(out)
        }
        7 => match info {
            20 => Cbor::Bool(false),
            21 => Cbor::Bool(true),
            22 => Cbor::Null,
            _ => return Err(CryptoError::Malformed), // floats, undefined, other simple values
        },
        _ => return Err(CryptoError::Malformed), // tags
    })
}

/// Encodes in the preferred (shortest) form, map entries in the order given.
pub fn encode(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

/// Like `encode`, into a buffer the caller owns, so a caller holding key material can pre-size and wipe it.
pub(super) fn encode_into(value: &Cbor, out: &mut Vec<u8>) {
    match value {
        Cbor::Uint(n) => head(out, 0, *n),
        Cbor::Nint(n) => head(out, 1, *n),
        Cbor::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Cbor::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Cbor::Array(a) => {
            head(out, 4, a.len() as u64);
            a.iter().for_each(|v| encode_into(v, out));
        }
        Cbor::Map(m) => {
            head(out, 5, m.len() as u64);
            for (k, v) in m {
                encode_into(k, out);
                encode_into(v, out);
            }
        }
        Cbor::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Cbor::Null => out.push(0xf6),
    }
}

/// The length `encode` gives, so a caller holding secrets can size its buffer once.
pub(super) fn encoded_len(value: &Cbor) -> usize {
    let head = |n: u64| match n {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    };
    match value {
        Cbor::Uint(n) | Cbor::Nint(n) => head(*n),
        Cbor::Bytes(b) => head(b.len() as u64) + b.len(),
        Cbor::Text(t) => head(t.len() as u64) + t.len(),
        Cbor::Array(a) => head(a.len() as u64) + a.iter().map(encoded_len).sum::<usize>(),
        Cbor::Map(m) => head(m.len() as u64) + m.iter().map(|(k, v)| encoded_len(k) + encoded_len(v)).sum::<usize>(),
        Cbor::Bool(_) | Cbor::Null => 1,
    }
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if let Ok(n) = u8::try_from(n) {
        out.extend([m | 24, n]);
    } else if let Ok(n) = u16::try_from(n) {
        out.push(m | 25);
        out.extend(n.to_be_bytes());
    } else if let Ok(n) = u32::try_from(n) {
        out.push(m | 26);
        out.extend(n.to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend(n.to_be_bytes());
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn encoded_len_matches_encode() {
        let items = [0, 23, 24, 255, 256, 65535, 65536, u64::from(u32::MAX), u64::from(u32::MAX) + 1];
        let mut all: Vec<Cbor> = items.iter().flat_map(|n| [Cbor::Uint(*n), Cbor::Nint(*n)]).collect();
        all.extend([Cbor::bytes(vec![1; 30]), Cbor::text("tiếng"), Cbor::Bool(true), Cbor::Null]);
        all.push(Cbor::Array(all.clone()));
        all.push(Cbor::Map(vec![(Cbor::text("k"), Cbor::Array(all.clone()))]));
        for v in all {
            assert_eq!(encoded_len(&v), encode(&v).len());
        }
    }

    /// Compile-level: building the variants from `Zeroizing` fails to compile if they hold anything else.
    #[test]
    fn decoded_text_is_zeroizing() {
        assert_eq!(decode(&[0x61, b'a']).unwrap(), Cbor::Text(CborText(Zeroizing::new("a".to_owned()))));
        assert_eq!(decode(&[0x41, 1]).unwrap(), Cbor::Bytes(Zeroizing::new(vec![1])));
    }
}
