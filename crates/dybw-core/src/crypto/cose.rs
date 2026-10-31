//! COSE objects as Bitwarden's SDK (bitwarden-crypto) defines them: symmetric COSE_Key keys and COSE_Encrypt0
//! messages, which are EncString type 7.

use super::CryptoError;
use super::aead::{open, seal};
use super::cbor::{self, Cbor};
use crate::ports::Random;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// COSE header labels (RFC 9052) and key parameters (RFC 9053).
pub(super) const H_ALG: i64 = 1;
pub(super) const H_CRIT: i64 = 2;
pub(super) const H_CONTENT_TYPE: i64 = 3;
pub(super) const H_KID: i64 = 4;
pub(super) const H_IV: i64 = 5;
const K_KTY: i64 = 1;
const K_KID: i64 = 2;
const K_ALG: i64 = 3;
const K_OPS: i64 = 4;
const K_SYMMETRIC_KEY: i64 = -1;
const KTY_SYMMETRIC: i64 = 4;
/// Strings are padded to the next multiple of 32 bytes, to hide their exact length.
/// A padded COSE key is at least this long.
const KEY_MIN_LEN: usize = 65;
const TEXT_BLOCK: usize = 32;

/// A CBOR integer from a signed label or value.
pub(super) fn int(n: i64) -> Cbor {
    match u64::try_from(n) {
        Ok(u) => Cbor::Uint(u),
        Err(_) => Cbor::Nint(n.unsigned_abs() - 1),
    }
}

/// The value under `label` in a CBOR map.
pub(super) fn get(map: &[(Cbor, Cbor)], label: i64) -> Option<&Cbor> {
    let label = int(label);
    map.iter().find(|(k, _)| *k == label).map(|(_, v)| v)
}

pub(super) fn as_map(v: &Cbor) -> Result<&[(Cbor, Cbor)], CryptoError> {
    match v {
        Cbor::Map(m) => Ok(m),
        _ => Err(CryptoError::Malformed),
    }
}

/// Copies the byte string under `label` into `out`, which must be exactly its length.
fn bytes_into(map: &[(Cbor, Cbor)], label: i64, out: &mut [u8]) -> Result<(), CryptoError> {
    match get(map, label) {
        Some(Cbor::Bytes(b)) if b.len() == out.len() => {
            out.copy_from_slice(b);
            Ok(())
        }
        _ => Err(CryptoError::Malformed),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseAlgorithm {
    /// Plain AES-256-GCM (COSE 3, 12-byte nonce): only for a DataEnvelope's content key, never for an EncString.
    Aes256Gcm,
    Xaes256Gcm,
    XChaCha20Poly1305,
}

impl CoseAlgorithm {
    /// Private-use COSE algorithm values from the SDK.
    pub(super) fn number(self) -> i64 {
        match self {
            CoseAlgorithm::Aes256Gcm => 3,
            CoseAlgorithm::XChaCha20Poly1305 => -70000,
            CoseAlgorithm::Xaes256Gcm => -70010,
        }
    }

    pub(super) fn nonce_size(self) -> usize {
        match self {
            CoseAlgorithm::Aes256Gcm => 12,
            CoseAlgorithm::Xaes256Gcm | CoseAlgorithm::XChaCha20Poly1305 => 24,
        }
    }

    pub(super) fn value(self) -> Cbor {
        int(self.number())
    }

    /// `cek` allows plain AES-256-GCM, whose random 96-bit nonce is safe only under a key that seals once: a content
    /// key. User keys, item keys and EncString type 7 take the two extended-nonce algorithms only.
    pub(super) fn from_value(v: Option<&Cbor>, cek: bool) -> Result<Self, CryptoError> {
        let all = [CoseAlgorithm::XChaCha20Poly1305, CoseAlgorithm::Xaes256Gcm, CoseAlgorithm::Aes256Gcm];
        all.into_iter().take(if cek { 3 } else { 2 }).find(|a| Some(&a.value()) == v).ok_or(CryptoError::Malformed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyOp {
    Encrypt = 3,
    Decrypt = 4,
    WrapKey = 5,
    UnwrapKey = 6,
}

impl KeyOp {
    fn from_value(v: &Cbor) -> Result<Self, CryptoError> {
        [KeyOp::Decrypt, KeyOp::Encrypt, KeyOp::WrapKey, KeyOp::UnwrapKey]
            .into_iter()
            .find(|op| *v == int(*op as i64))
            .ok_or(CryptoError::Malformed)
    }
}

/// What a COSE message holds, authenticated in its protected header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentFormat {
    Utf8,
    LegacyKey,
    CoseKey,
    Pkcs8,
    OctetStream,
}

impl ContentFormat {
    const ALL: [ContentFormat; 5] = [
        ContentFormat::Utf8,
        ContentFormat::LegacyKey,
        ContentFormat::CoseKey,
        ContentFormat::Pkcs8,
        ContentFormat::OctetStream,
    ];

    fn value(self) -> Cbor {
        match self {
            ContentFormat::Utf8 => Cbor::text("application/x.bitwarden.utf8-padded"),
            ContentFormat::LegacyKey => Cbor::text("application/x.bitwarden.legacy-key"),
            ContentFormat::CoseKey => int(101), // CoAP content format application/cose-key
            ContentFormat::Pkcs8 => int(284),   // application/pkcs8
            ContentFormat::OctetStream => int(42),
        }
    }
}

/// A symmetric COSE key. Private fields, wiped on drop, no `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CoseKey {
    #[zeroize(skip)]
    id: [u8; 16],
    #[zeroize(skip)]
    alg: CoseAlgorithm,
    #[zeroize(skip)]
    ops: Vec<KeyOp>,
    key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for CoseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CoseKey(<redacted>)")
    }
}

impl CoseKey {
    pub fn generate(alg: CoseAlgorithm, rng: &impl Random) -> Result<Self, CryptoError> {
        let (mut id, mut key) = ([0; 16], Zeroizing::new([0; 32]));
        rng.fill(&mut id)?;
        rng.fill(key.as_mut())?;
        Ok(CoseKey { id, alg, ops: all_ops(), key })
    }

    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    pub(super) fn alg(&self) -> CoseAlgorithm {
        self.alg
    }

    /// The raw 32-byte key, for the subkeys of `key.rs`.
    pub(super) fn secret(&self) -> &[u8; 32] {
        &self.key
    }

    /// Whether the key may only decrypt, as an SDK content key is stored.
    pub fn decrypt_only(&self) -> bool {
        self.ops == [KeyOp::Decrypt]
    }

    /// The same key, narrowed to decrypting.
    pub(super) fn into_decrypt_only(mut self) -> Self {
        self.ops = vec![KeyOp::Decrypt];
        self
    }

    pub(super) fn require(&self, op: KeyOp) -> Result<(), CryptoError> {
        self.ops.contains(&op).then_some(()).ok_or(CryptoError::WrongKey)
    }
}

fn all_ops() -> Vec<KeyOp> {
    vec![KeyOp::Decrypt, KeyOp::Encrypt, KeyOp::WrapKey, KeyOp::UnwrapKey]
}

/// Reads an unpadded COSE_Key.
pub fn parse_cose_key(bytes: &[u8]) -> Result<CoseKey, CryptoError> {
    parse_cose_key_as(bytes, false)
}

/// Like `parse_cose_key`; `cek` also accepts an AES-256-GCM content key.
pub(super) fn parse_cose_key_as(bytes: &[u8], cek: bool) -> Result<CoseKey, CryptoError> {
    let mut v = cbor::decode(bytes)?;
    let key = parse_map(&v, cek);
    v.zeroize();
    key
}

fn parse_map(v: &Cbor, cek: bool) -> Result<CoseKey, CryptoError> {
    let m = as_map(v)?;
    if get(m, K_KTY) != Some(&int(KTY_SYMMETRIC)) {
        return Err(CryptoError::Malformed);
    }
    let ops = match get(m, K_OPS) {
        None => Vec::new(), // no key_ops, no operations (the plugin's `?? []`)
        Some(Cbor::Array(a)) => a.iter().map(KeyOp::from_value).collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(CryptoError::Malformed),
    };
    // Distinct ops only: at most four, so the encoded key always fits `encode_cose_key`'s buffer.
    if !ops.iter().all(|o| ops.iter().filter(|p| *p == o).count() == 1) {
        return Err(CryptoError::Malformed);
    }
    let (mut id, mut key) = ([0; 16], Zeroizing::new([0; 32]));
    bytes_into(m, K_KID, &mut id)?;
    bytes_into(m, K_SYMMETRIC_KEY, key.as_mut())?;
    Ok(CoseKey { id, alg: CoseAlgorithm::from_value(get(m, K_ALG), cek)?, ops, key })
}

/// The COSE_Key bytes, in coset's order: kty, kid, alg, key_ops, then the key itself.
pub fn encode_cose_key(k: &CoseKey) -> Zeroizing<Vec<u8>> {
    let mut map = Cbor::Map(vec![
        (int(K_KTY), int(KTY_SYMMETRIC)),
        (int(K_KID), Cbor::bytes(k.id.to_vec())),
        (int(K_ALG), k.alg.value()),
        (int(K_OPS), Cbor::Array(k.ops.iter().map(|op| int(*op as i64)).collect())),
        (int(K_SYMMETRIC_KEY), Cbor::bytes(k.key.to_vec())),
    ]);
    // A COSE_Key is under 128 bytes, so the buffer never grows and leaves no unwiped copy behind.
    let mut out = Zeroizing::new(Vec::with_capacity(128));
    cbor::encode_into(&map, &mut out);
    map.zeroize();
    out
}

/// A COSE key in Bitwarden's byte format (the SDK's `pad_key`): the encoding padded to at least 65 bytes, so it is
/// never mistaken for a 32 or 64-byte legacy key.
pub(super) fn padded_key_bytes(k: &CoseKey) -> Zeroizing<Vec<u8>> {
    let mut v = encode_cose_key(k);
    let n = KEY_MIN_LEN.saturating_sub(v.len()).max(1);
    let len = v.len() + n;
    v.resize(len, n as u8);
    v
}

/// Appends N bytes of value N, at least one, until the length reaches `min_len`.
pub fn pad(bytes: &[u8], min_len: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let n = min_len.saturating_sub(bytes.len()).max(1);
    let n_byte = u8::try_from(n).map_err(|_| CryptoError::Malformed)?;
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() + n));
    out.extend_from_slice(bytes);
    out.resize(bytes.len() + n, n_byte);
    Ok(out)
}

/// Removes the padding `pad` added: the last byte says how many bytes to drop.
pub fn unpad(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let n = usize::from(bytes.last().copied().unwrap_or(0));
    if n == 0 || n > bytes.len() {
        return Err(CryptoError::Malformed);
    }
    Ok(Zeroizing::new(bytes.split_at(bytes.len() - n).0.to_vec()))
}

pub(super) fn enc_structure(protected: &[u8]) -> Vec<u8> {
    cbor::encode(&Cbor::Array(vec![Cbor::text("Encrypt0"), Cbor::bytes(protected.to_vec()), Cbor::bytes(vec![])]))
}

fn protected_header(key: &CoseKey, format: ContentFormat) -> Vec<u8> {
    cbor::encode(&Cbor::Map(vec![
        (int(H_ALG), key.alg.value()),
        (int(H_CONTENT_TYPE), format.value()),
        (int(H_KID), Cbor::bytes(key.id.to_vec())),
    ]))
}

/// The byte length of the COSE_Encrypt0 `cose_encrypt` builds for `len` bytes of text, without encrypting: the text
/// is padded to its block, and both AEADs add a 16-byte tag.
pub fn cose_text_len(key: &CoseKey, len: usize) -> usize {
    let ct = TEXT_BLOCK * (1 + len / TEXT_BLOCK) + 16;
    let unprotected = Cbor::Map(vec![(int(H_IV), Cbor::bytes(vec![0; key.alg.nonce_size()]))]);
    let message = Cbor::Array(vec![
        Cbor::bytes(protected_header(key, ContentFormat::Utf8)),
        unprotected,
        Cbor::bytes(vec![0; ct]),
    ]);
    cbor::encode(&message).len()
}

/// Encrypts into a COSE_Encrypt0 and returns its base64, the body of an EncString type 7 (without the `7.`).
pub fn cose_encrypt(
    key: &CoseKey,
    plain: &[u8],
    format: ContentFormat,
    rng: &impl Random,
) -> Result<String, CryptoError> {
    key.require(KeyOp::Encrypt)?;
    if key.alg == CoseAlgorithm::Aes256Gcm {
        return Err(CryptoError::WrongKey);
    }
    let protected = protected_header(key, format);
    let padded;
    let data: &[u8] = if format == ContentFormat::Utf8 {
        padded = pad(plain, TEXT_BLOCK * (1 + plain.len() / TEXT_BLOCK))?;
        &padded
    } else {
        plain
    };
    let mut nonce = vec![0u8; key.alg.nonce_size()];
    rng.fill(&mut nonce)?;
    let ct = seal(key.alg, &key.key, &nonce, data, &enc_structure(&protected))?;
    let unprotected = Cbor::Map(vec![(int(H_IV), Cbor::bytes(nonce.to_vec()))]);
    Ok(B64.encode(cbor::encode(&Cbor::Array(vec![Cbor::bytes(protected), unprotected, Cbor::bytes(ct)]))))
}

/// Authenticates and decrypts the base64 body of an EncString type 7. The message must name this key (algorithm and
/// key id); a text payload comes back unpadded. The caller checks that the returned format is one it accepts.
pub fn cose_decrypt(key: &CoseKey, s: &str) -> Result<(Zeroizing<Vec<u8>>, ContentFormat), CryptoError> {
    key.require(KeyOp::Decrypt)?;
    if key.alg == CoseAlgorithm::Aes256Gcm {
        return Err(CryptoError::WrongKey);
    }
    let bytes = B64.decode(s).map_err(|_| CryptoError::Malformed)?;
    let Cbor::Array(parts) = cbor::decode(&bytes)? else { return Err(CryptoError::Malformed) };
    let [Cbor::Bytes(protected), unprotected, Cbor::Bytes(ct)] = parts.as_slice() else {
        return Err(CryptoError::Malformed);
    };
    let header = cbor::decode(protected)?;
    let header = as_map(&header)?;
    if get(header, H_CRIT).is_some() {
        return Err(CryptoError::Malformed);
    }
    if CoseAlgorithm::from_value(get(header, H_ALG), false)? != key.alg {
        return Err(CryptoError::WrongKey);
    }
    if get(header, H_KID) != Some(&Cbor::bytes(key.id.to_vec())) {
        return Err(CryptoError::WrongKey);
    }
    let format = get(header, H_CONTENT_TYPE)
        .and_then(|v| ContentFormat::ALL.into_iter().find(|f| f.value() == *v))
        .ok_or(CryptoError::Malformed)?;
    let nonce = match get(as_map(unprotected)?, H_IV) {
        Some(Cbor::Bytes(n)) if n.len() == key.alg.nonce_size() => n,
        _ => return Err(CryptoError::Malformed),
    };
    let plain = open(key.alg, &key.key, nonce, ct, &enc_structure(protected))?;
    if format == ContentFormat::Utf8 {
        return Ok((unpad(&plain)?, format));
    }
    Ok((plain, format))
}
