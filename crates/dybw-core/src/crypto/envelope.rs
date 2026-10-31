//! Bitwarden's DataEnvelope: a COSE_Encrypt0 that seals a padded CBOR object under a content key (CEK). The protected
//! header names the CEK and says what the envelope holds (object namespace 2, a content namespace), so an envelope
//! cannot be passed off as another kind of object.

use super::CryptoError;
use super::aead::{open, seal};
use super::cbor::{self, Cbor};
use super::cose::{
    CoseAlgorithm, CoseKey, H_ALG, H_CONTENT_TYPE, H_CRIT, H_IV, H_KID, KeyOp, as_map, enc_structure, get, int, pad,
    parse_cose_key_as, unpad,
};
use crate::ports::Random;
use zeroize::Zeroizing;

/// COSE header label for the safe object namespace, and for the content namespace.
const H_OBJECT_NAMESPACE: i64 = -80002;
const H_CONTENT_NAMESPACE: i64 = -80001;
const OBJECT_DATA_ENVELOPE: u64 = 2;
const CONTENT_TYPE: &str = "application/x.bitwarden.cbor-padded";
/// The SDK's `DATA_ENVELOPE_PADDING_SIZE`: content is padded up to this length, with at least one byte.
const PADDING: usize = 64;

/// What an envelope's content is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeNamespace {
    VaultItem = 1,
}

/// A content key as the SDK stores it (in `wrapped_cek`): the same bytes as any COSE key (padded to at least 65, so a
/// 32 or 64-byte legacy key is refused), except that AES-256-GCM is allowed.
pub fn parse_cek(bytes: &[u8]) -> Result<CoseKey, CryptoError> {
    if matches!(bytes.len(), 32 | 64) {
        return Err(CryptoError::Malformed);
    }
    parse_cose_key_as(&unpad(bytes)?, true)
}

/// Opens an envelope with its CEK. The header must name this key and namespace; anything else is refused before
/// decryption. Returns the CBOR content, padding removed.
pub fn open_envelope(cek: &CoseKey, envelope: &[u8], ns: EnvelopeNamespace) -> Result<Cbor, CryptoError> {
    cek.require(KeyOp::Decrypt)?;
    let Cbor::Array(parts) = cbor::decode(envelope)? else { return Err(CryptoError::Malformed) };
    let [Cbor::Bytes(protected), unprotected, Cbor::Bytes(ct)] = parts.as_slice() else {
        return Err(CryptoError::Malformed);
    };
    let header = cbor::decode(protected)?;
    let header = as_map(&header)?;
    if get(header, H_CRIT).is_some() {
        return Err(CryptoError::Malformed);
    }
    if get(header, H_KID) != Some(&Cbor::bytes(cek.id().to_vec())) {
        return Err(CryptoError::WrongKey);
    }
    if get(header, H_OBJECT_NAMESPACE) != Some(&Cbor::Uint(OBJECT_DATA_ENVELOPE))
        || get(header, H_CONTENT_NAMESPACE) != Some(&Cbor::Uint(ns as u64))
        || get(header, H_CONTENT_TYPE) != Some(&Cbor::text(CONTENT_TYPE))
    {
        return Err(CryptoError::Malformed);
    }
    if CoseAlgorithm::from_value(get(header, H_ALG), true)? != cek.alg() {
        return Err(CryptoError::WrongKey);
    }
    let iv = match get(as_map(unprotected)?, H_IV) {
        Some(Cbor::Bytes(iv)) if iv.len() == cek.alg().nonce_size() => iv,
        _ => return Err(CryptoError::Malformed),
    };
    let plain = open(cek.alg(), cek.secret(), iv, ct, &enc_structure(protected))?;
    cbor::decode(&unpad(&plain)?)
}

/// Seals `content` under a fresh AES-256-GCM CEK, which comes back decrypt-only, as the SDK stores it.
pub fn seal_envelope(
    content: &Cbor,
    ns: EnvelopeNamespace,
    rng: &impl Random,
) -> Result<(Vec<u8>, CoseKey), CryptoError> {
    let cek = CoseKey::generate(CoseAlgorithm::Aes256Gcm, rng)?.into_decrypt_only();
    let protected = cbor::encode(&Cbor::Map(vec![
        (int(H_ALG), cek.alg().value()),
        (int(H_CONTENT_TYPE), Cbor::text(CONTENT_TYPE)),
        (int(H_KID), Cbor::bytes(cek.id().to_vec())),
        (int(H_OBJECT_NAMESPACE), Cbor::Uint(OBJECT_DATA_ENVELOPE)),
        (int(H_CONTENT_NAMESPACE), Cbor::Uint(ns as u64)),
    ]));
    let mut iv = vec![0u8; cek.alg().nonce_size()];
    rng.fill(&mut iv)?;
    // sized up front: a growing buffer would leave unwiped copies of the plaintext behind
    let mut encoded = Zeroizing::new(Vec::with_capacity(cbor::encoded_len(content)));
    cbor::encode_into(content, &mut encoded);
    let ct = seal(cek.alg(), cek.secret(), &iv, &pad(&encoded, PADDING)?, &enc_structure(&protected))?;
    let unprotected = Cbor::Map(vec![(int(H_IV), Cbor::bytes(iv))]);
    let envelope = cbor::encode(&Cbor::Array(vec![Cbor::bytes(protected), unprotected, Cbor::bytes(ct)]));
    Ok((envelope, cek))
}
