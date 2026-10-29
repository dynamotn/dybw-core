//! COSE objects as Bitwarden's SDK (bitwarden-crypto) defines them: symmetric COSE_Key keys and COSE_Encrypt0
//! messages, which are EncString type 7.

use super::CryptoError;
use super::aead::{xaes256gcm_decrypt, xaes256gcm_encrypt, xchacha20poly1305_decrypt, xchacha20poly1305_encrypt};
use super::cbor::{self, Cbor};
use crate::ports::Random;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// COSE header labels (RFC 9052) and key parameters (RFC 9053).
const H_ALG: i64 = 1;
const H_CRIT: i64 = 2;
const H_CONTENT_TYPE: i64 = 3;
const H_KID: i64 = 4;
const H_IV: i64 = 5;
const K_KTY: i64 = 1;
const K_KID: i64 = 2;
const K_ALG: i64 = 3;
const K_OPS: i64 = 4;
const K_SYMMETRIC_KEY: i64 = -1;
const KTY_SYMMETRIC: i64 = 4;
const NONCE_SIZE: usize = 24;
/// Strings are padded to the next multiple of 32 bytes, to hide their exact length.
const TEXT_BLOCK: usize = 32;

/// A CBOR integer from a signed label or value.
fn int(n: i64) -> Cbor {
    match u64::try_from(n) {
        Ok(u) => Cbor::Uint(u),
        Err(_) => Cbor::Nint(n.unsigned_abs() - 1),
    }
}

/// The value under `label` in a CBOR map.
fn get(map: &[(Cbor, Cbor)], label: i64) -> Option<&Cbor> {
    let label = int(label);
    map.iter().find(|(k, _)| *k == label).map(|(_, v)| v)
}

fn as_map(v: &Cbor) -> Result<&[(Cbor, Cbor)], CryptoError> {
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
    Xaes256Gcm,
    XChaCha20Poly1305,
}

impl CoseAlgorithm {
    /// Private-use COSE algorithm values from the SDK.
    fn value(self) -> Cbor {
        int(match self {
            CoseAlgorithm::XChaCha20Poly1305 => -70000,
            CoseAlgorithm::Xaes256Gcm => -70010,
        })
    }

    fn from_value(v: Option<&Cbor>) -> Result<Self, CryptoError> {
        [CoseAlgorithm::XChaCha20Poly1305, CoseAlgorithm::Xaes256Gcm]
            .into_iter()
            .find(|a| Some(&a.value()) == v)
            .ok_or(CryptoError::Malformed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOp {
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
            ContentFormat::Utf8 => Cbor::Text("application/x.bitwarden.utf8-padded".into()),
            ContentFormat::LegacyKey => Cbor::Text("application/x.bitwarden.legacy-key".into()),
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

    fn require(&self, op: KeyOp) -> Result<(), CryptoError> {
        self.ops.contains(&op).then_some(()).ok_or(CryptoError::WrongKey)
    }
}

fn all_ops() -> Vec<KeyOp> {
    vec![KeyOp::Decrypt, KeyOp::Encrypt, KeyOp::WrapKey, KeyOp::UnwrapKey]
}

/// Reads an unpadded COSE_Key.
pub fn parse_cose_key(bytes: &[u8]) -> Result<CoseKey, CryptoError> {
    let mut v = cbor::decode(bytes)?;
    let key = parse_map(&v);
    v.zeroize();
    key
}

fn parse_map(v: &Cbor) -> Result<CoseKey, CryptoError> {
    let m = as_map(v)?;
    if get(m, K_KTY) != Some(&int(KTY_SYMMETRIC)) {
        return Err(CryptoError::Malformed);
    }
    let ops = match get(m, K_OPS) {
        None => all_ops(),
        Some(Cbor::Array(a)) => a.iter().map(KeyOp::from_value).collect::<Result<_, _>>()?,
        Some(_) => return Err(CryptoError::Malformed),
    };
    let (mut id, mut key) = ([0; 16], Zeroizing::new([0; 32]));
    bytes_into(m, K_KID, &mut id)?;
    bytes_into(m, K_SYMMETRIC_KEY, key.as_mut())?;
    Ok(CoseKey { id, alg: CoseAlgorithm::from_value(get(m, K_ALG))?, ops, key })
}

/// The COSE_Key bytes, in coset's order: kty, kid, alg, key_ops, then the key itself.
pub fn encode_cose_key(k: &CoseKey) -> Zeroizing<Vec<u8>> {
    let mut map = Cbor::Map(vec![
        (int(K_KTY), int(KTY_SYMMETRIC)),
        (int(K_KID), Cbor::Bytes(k.id.to_vec())),
        (int(K_ALG), k.alg.value()),
        (int(K_OPS), Cbor::Array(k.ops.iter().map(|op| int(*op as i64)).collect())),
        (int(K_SYMMETRIC_KEY), Cbor::Bytes(k.key.to_vec())),
    ]);
    // A COSE_Key is under 128 bytes, so the buffer never grows and leaves no unwiped copy behind.
    let mut out = Zeroizing::new(Vec::with_capacity(128));
    cbor::encode_into(&map, &mut out);
    map.zeroize();
    out
}

/// A COSE key in Bitwarden's byte format: the encoding plus one padding byte (it is always 65 bytes or more, so the
/// padding is a single `0x01`).
pub(super) fn padded_key_bytes(k: &CoseKey) -> Zeroizing<Vec<u8>> {
    let mut v = encode_cose_key(k);
    v.push(1);
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

fn enc_structure(protected: &[u8]) -> Vec<u8> {
    cbor::encode(&Cbor::Array(vec![
        Cbor::Text("Encrypt0".into()),
        Cbor::Bytes(protected.to_vec()),
        Cbor::Bytes(vec![]),
    ]))
}

/// Encrypts into a COSE_Encrypt0 and returns its base64, the body of an EncString type 7 (without the `7.`).
pub fn cose_encrypt(
    key: &CoseKey,
    plain: &[u8],
    format: ContentFormat,
    rng: &impl Random,
) -> Result<String, CryptoError> {
    key.require(KeyOp::Encrypt)?;
    let protected = cbor::encode(&Cbor::Map(vec![
        (int(H_ALG), key.alg.value()),
        (int(H_CONTENT_TYPE), format.value()),
        (int(H_KID), Cbor::Bytes(key.id.to_vec())),
    ]));
    let padded;
    let data: &[u8] = if format == ContentFormat::Utf8 {
        padded = pad(plain, TEXT_BLOCK * (1 + plain.len() / TEXT_BLOCK))?;
        &padded
    } else {
        plain
    };
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill(&mut nonce)?;
    let aad = enc_structure(&protected);
    let ct = match key.alg {
        CoseAlgorithm::Xaes256Gcm => xaes256gcm_encrypt(&key.key, &nonce, data, &aad)?,
        CoseAlgorithm::XChaCha20Poly1305 => xchacha20poly1305_encrypt(&key.key, &nonce, data, &aad)?,
    };
    let unprotected = Cbor::Map(vec![(int(H_IV), Cbor::Bytes(nonce.to_vec()))]);
    Ok(B64.encode(cbor::encode(&Cbor::Array(vec![Cbor::Bytes(protected), unprotected, Cbor::Bytes(ct)]))))
}

/// Authenticates and decrypts the base64 body of an EncString type 7. The message must name this key (algorithm and
/// key id); a text payload comes back unpadded. The caller checks that the returned format is one it accepts.
pub fn cose_decrypt(key: &CoseKey, s: &str) -> Result<(Zeroizing<Vec<u8>>, ContentFormat), CryptoError> {
    key.require(KeyOp::Decrypt)?;
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
    if CoseAlgorithm::from_value(get(header, H_ALG))? != key.alg {
        return Err(CryptoError::WrongKey);
    }
    if get(header, H_KID) != Some(&Cbor::Bytes(key.id.to_vec())) {
        return Err(CryptoError::WrongKey);
    }
    let format = get(header, H_CONTENT_TYPE)
        .and_then(|v| ContentFormat::ALL.into_iter().find(|f| f.value() == *v))
        .ok_or(CryptoError::Malformed)?;
    let mut nonce = [0u8; NONCE_SIZE];
    bytes_into(as_map(unprotected)?, H_IV, &mut nonce)?;
    let aad = enc_structure(protected);
    let plain = match key.alg {
        CoseAlgorithm::Xaes256Gcm => xaes256gcm_decrypt(&key.key, &nonce, ct, &aad)?,
        CoseAlgorithm::XChaCha20Poly1305 => xchacha20poly1305_decrypt(&key.key, &nonce, ct, &aad)?,
    };
    if format == ContentFormat::Utf8 {
        return Ok((unpad(&plain)?, format));
    }
    Ok((plain, format))
}
