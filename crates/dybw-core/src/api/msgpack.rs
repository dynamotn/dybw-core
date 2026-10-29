//! A MessagePack decoder, just enough for the SignalR messages of the Bitwarden notifications hub. Input comes from
//! the network: every read is checked against the bytes left before anything is allocated and nesting is limited, so
//! malformed data is an error, never a hang or a huge allocation.

use std::collections::HashSet;

const MAX_DEPTH: usize = 32;
const MAX_SAFE_INT: u128 = (1 << 53) - 1;

/// Why a message could not be decoded. Messages name the problem, never the data.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MsgPackError {
    #[error("truncated MessagePack data")]
    Truncated,
    #[error("malformed MessagePack data")]
    Malformed,
    #[error("MessagePack data is nested too deeply")]
    TooDeep,
    #[error("SignalR message is too large")]
    TooLarge,
}

/// A decoded value. Map keys (strings or integers on the wire) are kept as strings, as the plugin does.
#[derive(Debug, Clone, PartialEq)]
pub enum Msg {
    Nil,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    Bin(Vec<u8>),
    Array(Vec<Msg>),
    Map(Vec<(String, Msg)>),
    Ext(i8, Vec<u8>),
    /// The timestamp extension (type -1), which .NET uses for `DateTime` values.
    Timestamp {
        seconds: i64,
        nanos: u32,
    },
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MsgPackError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(MsgPackError::Truncated)?;
        self.0 = rest;
        Ok(head)
    }

    /// A big-endian unsigned integer of `size` bytes (at most 8).
    fn be(&mut self, size: usize) -> Result<u64, MsgPackError> {
        Ok(self.take(size)?.iter().fold(0, |v, b| (v << 8) | u64::from(*b)))
    }

    /// A big-endian signed integer of `size` bytes, sign-extended.
    fn signed(&mut self, size: usize) -> Result<i128, MsgPackError> {
        let shift = 64 - 8 * size;
        Ok(i128::from(((self.be(size)? << shift) as i64) >> shift))
    }

    /// A length of at most 4 bytes.
    fn length(&mut self, size: usize) -> Result<usize, MsgPackError> {
        Ok(self.be(size)? as usize)
    }

    /// An item count. Every element takes at least one byte, so a count beyond the bytes left is refused before
    /// anything is reserved.
    fn count(&mut self, size: usize) -> Result<usize, MsgPackError> {
        let n = self.length(size)?;
        if n > self.0.len() {
            return Err(MsgPackError::Truncated);
        }
        Ok(n)
    }

    fn string(&mut self, size: usize) -> Result<String, MsgPackError> {
        let n = self.length(size)?;
        std::str::from_utf8(self.take(n)?).map(str::to_owned).map_err(|_| MsgPackError::Malformed)
    }

    fn bin(&mut self, size: usize) -> Result<Msg, MsgPackError> {
        let n = self.length(size)?;
        Ok(Msg::Bin(self.take(n)?.to_vec()))
    }

    fn array(&mut self, n: usize, depth: usize) -> Result<Msg, MsgPackError> {
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(read(self, depth + 1)?);
        }
        Ok(Msg::Array(out))
    }

    fn map(&mut self, n: usize, depth: usize) -> Result<Msg, MsgPackError> {
        let (mut out, mut seen) = (Vec::new(), HashSet::new());
        for _ in 0..n {
            let key = match read(self, depth + 1)? {
                Msg::Str(s) => s,
                // Beyond 2^53 the plugin sees a bigint, which it refuses as a key.
                Msg::Int(i) if i.unsigned_abs() <= MAX_SAFE_INT => i.to_string(),
                _ => return Err(MsgPackError::Malformed),
            };
            // A set, not a scan: a 1 MiB frame holds ~500k entries. The plugin keeps the last duplicate; refusing is stricter.
            if !seen.insert(key.clone()) {
                return Err(MsgPackError::Malformed);
            }
            out.push((key, read(self, depth + 1)?));
        }
        Ok(Msg::Map(out))
    }

    fn ext(&mut self, n: usize) -> Result<Msg, MsgPackError> {
        let kind = self.be(1)? as u8 as i8;
        let data = self.take(n)?;
        if kind != -1 {
            return Ok(Msg::Ext(kind, data.to_vec()));
        }
        let mut data = Reader(data);
        let (seconds, nanos) = match n {
            4 => (data.be(4)? as i64, 0),
            8 => {
                let v = data.be(8)?;
                ((v & ((1 << 34) - 1)) as i64, (v >> 34) as u32)
            }
            12 => {
                let nanos = data.be(4)? as u32;
                (data.be(8)? as i64, nanos)
            }
            _ => return Err(MsgPackError::Malformed),
        };
        Ok(Msg::Timestamp { seconds, nanos })
    }
}

/// Decodes one MessagePack value that must fill `bytes` exactly.
pub fn decode_msgpack(bytes: &[u8]) -> Result<Msg, MsgPackError> {
    let mut r = Reader(bytes);
    let v = read(&mut r, 0)?;
    if !r.0.is_empty() {
        return Err(MsgPackError::Malformed);
    }
    Ok(v)
}

fn read(r: &mut Reader, depth: usize) -> Result<Msg, MsgPackError> {
    if depth > MAX_DEPTH {
        return Err(MsgPackError::TooDeep);
    }
    let b = r.be(1)? as u8;
    Ok(match b {
        0x00..=0x7f => Msg::Int(i128::from(b)),
        0x80..=0x8f => return r.map(usize::from(b & 0x0f), depth),
        0x90..=0x9f => return r.array(usize::from(b & 0x0f), depth),
        0xa0..=0xbf => {
            let n = usize::from(b & 0x1f);
            let s = std::str::from_utf8(r.take(n)?).map_err(|_| MsgPackError::Malformed)?;
            Msg::Str(s.to_owned())
        }
        0xc0 => Msg::Nil,
        0xc2 => Msg::Bool(false),
        0xc3 => Msg::Bool(true),
        0xc4 => return r.bin(1),
        0xc5 => return r.bin(2),
        0xc6 => return r.bin(4),
        0xc7 => {
            let n = r.length(1)?;
            return r.ext(n);
        }
        0xc8 => {
            let n = r.length(2)?;
            return r.ext(n);
        }
        0xc9 => {
            let n = r.length(4)?;
            return r.ext(n);
        }
        0xca => Msg::Float(f64::from(f32::from_bits(r.be(4)? as u32))),
        0xcb => Msg::Float(f64::from_bits(r.be(8)?)),
        0xcc => Msg::Int(i128::from(r.be(1)?)),
        0xcd => Msg::Int(i128::from(r.be(2)?)),
        0xce => Msg::Int(i128::from(r.be(4)?)),
        0xcf => Msg::Int(i128::from(r.be(8)?)),
        0xd0 => Msg::Int(r.signed(1)?),
        0xd1 => Msg::Int(r.signed(2)?),
        0xd2 => Msg::Int(r.signed(4)?),
        0xd3 => Msg::Int(r.signed(8)?),
        0xd4 => return r.ext(1),
        0xd5 => return r.ext(2),
        0xd6 => return r.ext(4),
        0xd7 => return r.ext(8),
        0xd8 => return r.ext(16),
        0xd9 => Msg::Str(r.string(1)?),
        0xda => Msg::Str(r.string(2)?),
        0xdb => Msg::Str(r.string(4)?),
        0xdc => {
            let n = r.count(2)?;
            return r.array(n, depth);
        }
        0xdd => {
            let n = r.count(4)?;
            return r.array(n, depth);
        }
        0xde => {
            let n = r.count(2)?;
            return r.map(n, depth);
        }
        0xdf => {
            let n = r.count(4)?;
            return r.map(n, depth);
        }
        0xe0..=0xff => Msg::Int(i128::from(b as i8)),
        0xc1 => return Err(MsgPackError::Malformed), // never used
    })
}

/// Splits a SignalR binary payload into its messages: each is prefixed with its length as a VarInt (7 bits per byte,
/// low bits first, at most 5 bytes).
pub fn split_signalr_frames(bytes: &[u8], max_message: usize) -> Result<Vec<&[u8]>, MsgPackError> {
    let (mut out, mut rest) = (Vec::new(), bytes);
    while !rest.is_empty() {
        let (mut len, mut used, mut done) = (0u64, 0, false);
        for (i, b) in rest.iter().take(5).enumerate() {
            len |= u64::from(b & 0x7f) << (7 * i);
            used = i + 1;
            done = b & 0x80 == 0;
            if done {
                break;
            }
        }
        if !done {
            return Err(MsgPackError::Malformed);
        }
        if len > max_message as u64 {
            return Err(MsgPackError::TooLarge);
        }
        let (frame, tail) = rest.split_at(used).1.split_at_checked(len as usize).ok_or(MsgPackError::Truncated)?;
        out.push(frame);
        rest = tail;
    }
    Ok(out)
}
