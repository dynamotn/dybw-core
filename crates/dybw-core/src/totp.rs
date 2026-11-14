//! TOTP codes from a Bitwarden login's `totp` field (profiles §7): RFC 6238 over HMAC-SHA1, -SHA256 or -SHA512,
//! and Steam Guard codes. Pure: the caller gives the time and gets the code; the secret never leaves the key.
//!
//! The field holds one of:
//! - an `otpauth://totp/<label>?secret=…&algorithm=…&digits=…&period=…` URI (only `secret` is required; the
//!   scheme, the type and the parameter names are case-insensitive, unknown parameters such as `issuer` are
//!   ignored, and a parameter given twice is refused);
//! - a bare base32 secret, parsed as rbw 1.15 does: spaces anywhere, either case, padding optional;
//! - `steam://<base32 secret>`: five characters from the Steam alphabet, HMAC-SHA1, 30-second period.
//!
//! Ranges follow the official clients. The web, desktop and browser clients (`libs/common/src/vault/services/
//! totp.service.ts`) hand the key to Bitwarden's SDK, whose parser is `sdk-internal`
//! `crates/bitwarden-vault/src/totp.rs` (`impl FromStr for Totp`, read on 2026-11-15): `digits` parses as a
//! `u32` clamped to `0..=10`, `period` as a `u32` raised to at least 1, and an unknown algorithm falls back to
//! SHA-1. Here the same ranges are enforced instead of clamped: `digits` in `1..=10` (0 would make an empty
//! code), `period` in `1..=u32::MAX` seconds, and an unknown algorithm is an error.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// The digits of a code when the URI does not say, and of a bare secret.
pub const DEFAULT_DIGITS: u8 = 6;
/// The period in seconds when the URI does not say, and of a bare or Steam secret.
pub const DEFAULT_PERIOD: u32 = 30;
/// The fewest digits a code may have.
pub const MIN_DIGITS: u8 = 1;
/// The most digits a code may have (the official clients' upper bound).
pub const MAX_DIGITS: u8 = 10;
/// The length of a Steam code.
pub const STEAM_DIGITS: u8 = 5;
/// The characters of a Steam code.
pub const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// How a code is computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
    /// HMAC-SHA1, written in the Steam alphabet.
    Steam,
}

/// Why a `totp` field was refused. Messages never carry the secret nor the field's text; the range errors name only
/// the number given for `digits` or `period`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    #[error("the TOTP secret is empty")]
    EmptySecret,
    #[error("the TOTP secret is not valid base32")]
    InvalidBase32,
    #[error("the TOTP key is neither base32, an otpauth:// URI nor a steam:// URI")]
    UnsupportedScheme,
    #[error("the otpauth URI is not of type totp")]
    UnsupportedType,
    #[error("the otpauth URI is malformed")]
    MalformedUri,
    #[error("the otpauth URI has no secret")]
    MissingSecret,
    #[error("the otpauth URI gives the parameter {0} more than once")]
    DuplicateParameter(&'static str),
    #[error("unknown TOTP algorithm: expected SHA1, SHA256 or SHA512")]
    UnknownAlgorithm,
    #[error("the TOTP digits is not a number")]
    InvalidDigits,
    #[error("the TOTP digits {0} is outside {MIN_DIGITS}..={MAX_DIGITS}")]
    DigitsOutOfRange(u64),
    #[error("the TOTP period is not a number")]
    InvalidPeriod,
    #[error("the TOTP period {0} is outside 1..={max} seconds", max = u32::MAX)]
    PeriodOutOfRange(u64),
}

impl TotpError {
    /// A stable code for the error, as the vectors name it.
    pub fn code(&self) -> &'static str {
        match self {
            TotpError::EmptySecret => "empty-secret",
            TotpError::InvalidBase32 => "invalid-base32",
            TotpError::UnsupportedScheme => "unsupported-scheme",
            TotpError::UnsupportedType => "unsupported-type",
            TotpError::MalformedUri => "malformed-uri",
            TotpError::MissingSecret => "missing-secret",
            TotpError::DuplicateParameter(_) => "duplicate-parameter",
            TotpError::UnknownAlgorithm => "unknown-algorithm",
            TotpError::InvalidDigits => "invalid-digits",
            TotpError::DigitsOutOfRange(_) => "digits-out-of-range",
            TotpError::InvalidPeriod => "invalid-period",
            TotpError::PeriodOutOfRange(_) => "period-out-of-range",
        }
    }
}

/// A parsed `totp` field. The secret is wiped on drop; no `Clone`, and `Debug` hides it.
pub struct TotpKey {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
}

impl fmt::Debug for TotpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpKey")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

/// A code and how long it stays valid. The code is wiped on drop; `Debug` hides it.
pub struct TotpCode {
    code: Zeroizing<String>,
    seconds_remaining: u64,
}

impl fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpCode")
            .field("code", &"<redacted>")
            .field("seconds_remaining", &self.seconds_remaining)
            .finish()
    }
}

impl TotpCode {
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Seconds until the next period starts, in `1..=period`: the code at `time + seconds_remaining` is the
    /// next one (`dybw code --next`).
    pub fn seconds_remaining(&self) -> u64 {
        self.seconds_remaining
    }
}

impl TotpKey {
    /// Parses a login's `totp` field. Leading and trailing whitespace is ignored.
    pub fn parse(text: &str) -> Result<TotpKey, TotpError> {
        let text = text.trim();
        if let Some(rest) = strip_prefix_ignore_case(text, "otpauth://") {
            parse_otpauth(rest)
        } else if let Some(rest) = strip_prefix_ignore_case(text, "steam://") {
            let secret = decode_base32(rest.as_bytes())?;
            Ok(TotpKey { secret, algorithm: Algorithm::Steam, digits: STEAM_DIGITS, period: DEFAULT_PERIOD })
        } else if text.contains(':') {
            Err(TotpError::UnsupportedScheme)
        } else {
            let secret = decode_base32(text.as_bytes())?;
            Ok(TotpKey { secret, algorithm: Algorithm::Sha1, digits: DEFAULT_DIGITS, period: DEFAULT_PERIOD })
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The length of a code: 5 for Steam.
    pub fn digits(&self) -> u8 {
        self.digits
    }

    /// The period in seconds.
    pub fn period(&self) -> u32 {
        self.period
    }

    /// The code at `unix_time` (seconds since the epoch), RFC 6238 with `T0 = 0`.
    pub fn generate(&self, unix_time: u64) -> TotpCode {
        let period = u64::from(self.period);
        let counter = (unix_time / period).to_be_bytes();
        let mac = match self.algorithm {
            Algorithm::Sha1 | Algorithm::Steam => hmac::<Hmac<Sha1>>(&self.secret, &counter),
            Algorithm::Sha256 => hmac::<Hmac<Sha256>>(&self.secret, &counter),
            Algorithm::Sha512 => hmac::<Hmac<Sha512>>(&self.secret, &counter),
        };
        let mut binary = truncate(&mac);
        let code = match self.algorithm {
            Algorithm::Steam => steam_code(binary),
            _ => decimal_code(binary, self.digits),
        };
        binary.zeroize();
        TotpCode { code, seconds_remaining: period - unix_time % period }
    }
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| text.get(prefix.len()..).unwrap_or_default())
}

/// `rest` is what follows `otpauth://`: `<type>/<label>?<query>#<fragment>`.
fn parse_otpauth(rest: &str) -> Result<TotpKey, TotpError> {
    let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let kind = path.split_once('/').map_or(path, |(kind, _)| kind);
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(TotpError::UnsupportedType);
    }

    let mut secret = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (slot, label) = if name.eq_ignore_ascii_case("secret") {
            (&mut secret, "secret")
        } else if name.eq_ignore_ascii_case("algorithm") {
            (&mut algorithm, "algorithm")
        } else if name.eq_ignore_ascii_case("digits") {
            (&mut digits, "digits")
        } else if name.eq_ignore_ascii_case("period") {
            (&mut period, "period")
        } else {
            continue;
        };
        if slot.is_some() {
            return Err(TotpError::DuplicateParameter(label));
        }
        *slot = Some(percent_decode(value)?);
    }

    let algorithm = match algorithm {
        None => Algorithm::Sha1,
        Some(v) if v.eq_ignore_ascii_case(b"sha1") => Algorithm::Sha1,
        Some(v) if v.eq_ignore_ascii_case(b"sha256") => Algorithm::Sha256,
        Some(v) if v.eq_ignore_ascii_case(b"sha512") => Algorithm::Sha512,
        Some(_) => return Err(TotpError::UnknownAlgorithm),
    };
    let digits = match digits {
        None => DEFAULT_DIGITS,
        Some(v) => {
            let n = parse_number(&v).ok_or(TotpError::InvalidDigits)?;
            u8::try_from(n)
                .ok()
                .filter(|d| (MIN_DIGITS..=MAX_DIGITS).contains(d))
                .ok_or(TotpError::DigitsOutOfRange(n))?
        }
    };
    let period = match period {
        None => DEFAULT_PERIOD,
        Some(v) => {
            let n = parse_number(&v).ok_or(TotpError::InvalidPeriod)?;
            u32::try_from(n).ok().filter(|p| *p >= 1).ok_or(TotpError::PeriodOutOfRange(n))?
        }
    };
    let secret = decode_base32(&secret.ok_or(TotpError::MissingSecret)?)?;
    Ok(TotpKey { secret, algorithm, digits, period })
}

/// Decodes a query value: `%XX` escapes, and `+` as a space (form encoding, as `url`'s `query_pairs` does).
fn percent_decode(value: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        let byte = match b {
            b'+' => b' ',
            b'%' => {
                let hi = bytes.next().and_then(hex_digit);
                let lo = bytes.next().and_then(hex_digit);
                hi.zip(lo).map(|(hi, lo)| hi << 4 | lo).ok_or(TotpError::MalformedUri)?
            }
            other => other,
        };
        out.push(byte);
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// A non-empty run of ASCII digits; a value too large for `u64` saturates (it is out of every range).
fn parse_number(text: &[u8]) -> Option<u64> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(text.iter().fold(0u64, |n, d| n.saturating_mul(10).saturating_add(u64::from(d - b'0'))))
}

/// RFC 4648 base32, as rbw 1.15 accepts it: spaces are dropped, either case, trailing `=` padding optional.
/// A length no base32 text can have (1, 3 or 6 characters past a multiple of 8) is refused; the unused low bits
/// of the last character are ignored.
fn decode_base32(text: &[u8]) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8 + 1));
    let mut buffer = 0u32;
    let mut bits = 0u32;
    let mut chars = 0usize;
    let mut padding = false;
    let mut result = Ok(());
    for &c in text.iter().filter(|c| **c != b' ') {
        let value = match c.to_ascii_uppercase() {
            b'=' => {
                padding = true;
                continue;
            }
            _ if padding => None,
            u @ b'A'..=b'Z' => Some(u - b'A'),
            d @ b'2'..=b'7' => Some(d - b'2' + 26),
            _ => None,
        };
        let Some(value) = value else {
            result = Err(TotpError::InvalidBase32);
            break;
        };
        chars += 1;
        buffer = (buffer << 5 | u32::from(value)) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    buffer.zeroize();
    result?;
    match chars % 8 {
        _ if chars == 0 => Err(TotpError::EmptySecret),
        1 | 3 | 6 => Err(TotpError::InvalidBase32),
        _ => Ok(out),
    }
}

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
fn hmac<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

/// RFC 4226 §5.3 dynamic truncation: 31 bits from the offset the last nibble names.
fn truncate(mac: &[u8]) -> u32 {
    let offset = usize::from(mac.last().copied().unwrap_or_default() & 0x0f);
    let word = mac.iter().skip(offset).take(4).fold(0u32, |w, b| w << 8 | u32::from(*b));
    word & 0x7fff_ffff
}

/// The last `digits` decimal digits, zero-padded. Written by hand into wiped buffers: `format!` would leave the code
/// in `core::fmt`'s own stack buffer. 31 bits never need more than `MAX_DIGITS` digits.
fn decimal_code(binary: u32, digits: u8) -> Zeroizing<String> {
    let mut value = binary;
    let mut all = Zeroizing::new([b'0'; MAX_DIGITS as usize]);
    for slot in all.iter_mut().rev() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let mut code = Zeroizing::new(String::with_capacity(usize::from(digits)));
    for b in all.iter().skip(usize::from(MAX_DIGITS - digits)) {
        code.push(char::from(*b));
    }
    code
}

#[expect(clippy::indexing_slicing, reason = "an index modulo 26 is inside the 26-character alphabet")]
fn steam_code(mut binary: u32) -> Zeroizing<String> {
    let mut code = Zeroizing::new(String::with_capacity(usize::from(STEAM_DIGITS)));
    for _ in 0..STEAM_DIGITS {
        code.push(char::from(STEAM_ALPHABET[(binary % 26) as usize]));
        binary /= 26;
    }
    binary.zeroize();
    code
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
#[path = "totp_tests.rs"]
mod tests;
