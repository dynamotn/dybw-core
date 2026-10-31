//! Signing keys and COSE_Sign1 verification as Bitwarden's SDK defines them, for the signed security state of a v2
//! account (ADR 0019). The core never signs: it derives the verifying key from the account's own signing key, so the
//! server's `verifyingKey` and `securityVersion` are never trusted.

use super::CryptoError;
use super::cbor::{self, Cbor};
use super::cose::{ContentFormat, H_ALG, H_CONTENT_TYPE, H_CRIT, H_KID, as_map, bytes_into, get, int};
use super::key::SymmetricKey;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ml_dsa::signature::{Keypair, Verifier};
use ml_dsa::{B32, MlDsa44};
use std::fmt;
use zeroize::{ZeroizeOnDrop, Zeroizing};

// COSE_Key labels (RFC 9052, RFC 9053, and the AKP key type of the ML-DSA draft).
const K_KTY: i64 = 1;
const K_KID: i64 = 2;
const K_ALG: i64 = 3;
const KTY_OKP: i64 = 1;
const KTY_AKP: i64 = 7;
const OKP_CRV: i64 = -1;
const OKP_D: i64 = -4;
const CRV_ED25519: i64 = 6;
const AKP_PRIV: i64 = -2;
const ALG_EDDSA: i64 = -8;
const ALG_MLDSA44: i64 = -48;
/// The SDK's signing namespace header, and its `SecurityState` namespace.
const H_SIGNING_NAMESPACE: i64 = -80000;
pub(super) const NS_SECURITY_STATE: i64 = 2;
/// CoAP content format 60: the payload is CBOR.
const CONTENT_CBOR: u64 = 60;

/// An account's signing key (Ed25519 or ML-DSA-44), only ever used here to derive its verifying key. Wiped on drop,
/// no `Clone`, redacted in `Debug`.
pub struct SigningKey {
    id: [u8; 16],
    inner: Inner,
}

// Boxed: the enum stays small, and a key is not copied again when a `SigningKey` moves.
enum Inner {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    MlDsa44(Box<ml_dsa::SigningKey<MlDsa44>>),
}

// Both inner keys wipe themselves on drop (`sign_tests::signing_keys_are_wiped` fails to build if that stops).
impl ZeroizeOnDrop for SigningKey {}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

/// The public half of a signing key, with the key's id.
pub(super) struct VerifyingKey {
    pub(super) id: [u8; 16],
    pub(super) key: RawVerifyingKey,
}

pub(super) enum RawVerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    MlDsa44(Box<ml_dsa::VerifyingKey<MlDsa44>>),
}

impl SigningKey {
    /// Reads an unpadded COSE_Key: OKP/EdDSA on curve Ed25519 with `d`, or AKP/ML-DSA-44 with the 32-byte seed in
    /// the private parameter (the expanded key is derived from the seed, as the SDK does).
    pub fn from_cose(bytes: &[u8]) -> Result<SigningKey, CryptoError> {
        let v = cbor::decode(bytes)?;
        let m = as_map(&v)?;
        let is = |label, value| get(m, label) == Some(&int(value));
        let mut id = [0; 16];
        bytes_into(m, K_KID, &mut id)?;
        let inner = if is(K_KTY, KTY_OKP) && is(K_ALG, ALG_EDDSA) && is(OKP_CRV, CRV_ED25519) {
            let mut d = Zeroizing::new([0; 32]);
            bytes_into(m, OKP_D, d.as_mut())?;
            Inner::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(&d)))
        } else if is(K_KTY, KTY_AKP) && is(K_ALG, ALG_MLDSA44) {
            let mut seed = Zeroizing::new(B32::default());
            bytes_into(m, AKP_PRIV, seed.as_mut_slice())?;
            Inner::MlDsa44(Box::new(ml_dsa::SigningKey::from_seed(&seed)))
        } else {
            return Err(CryptoError::Malformed);
        };
        Ok(SigningKey { id, inner })
    }

    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }

    pub(super) fn verifying_key(&self) -> VerifyingKey {
        let key = match &self.inner {
            Inner::Ed25519(k) => RawVerifyingKey::Ed25519(k.verifying_key()),
            Inner::MlDsa44(k) => RawVerifyingKey::MlDsa44(Box::new(k.verifying_key())),
        };
        VerifyingKey { id: self.id, key }
    }
}

impl VerifyingKey {
    fn alg(&self) -> Cbor {
        int(match self.key {
            RawVerifyingKey::Ed25519(_) => ALG_EDDSA,
            RawVerifyingKey::MlDsa44(_) => ALG_MLDSA44,
        })
    }

    /// Ed25519 in its strict form, ML-DSA-44 with the empty context, as the SDK verifies. A failure is `BadSignature`.
    pub(super) fn verify_raw(&self, signature: &[u8], data: &[u8]) -> Result<(), CryptoError> {
        let ok = match &self.key {
            RawVerifyingKey::Ed25519(k) => {
                ed25519_dalek::Signature::from_slice(signature).is_ok_and(|s| k.verify_strict(data, &s).is_ok())
            }
            RawVerifyingKey::MlDsa44(k) => {
                ml_dsa::Signature::<MlDsa44>::try_from(signature).is_ok_and(|s| k.verify(data, &s).is_ok())
            }
        };
        ok.then_some(()).ok_or(CryptoError::BadSignature)
    }
}

/// Decrypts the account's wrapped signing key: an EncString type 7 under the user key that says it holds a COSE key.
pub fn unwrap_signing_key(user: &SymmetricKey, wrapped: &str) -> Result<SigningKey, CryptoError> {
    match user.open(wrapped, &[ContentFormat::CoseKey])? {
        (bytes, Some(_)) => SigningKey::from_cose(&bytes),
        // A type 2 value carries no content format, so it cannot say it holds a COSE key.
        (_, None) => Err(CryptoError::Malformed),
    }
}

/// Verifies a signed security state (base64 of a COSE_Sign1) with the verifying key derived from `key`, and returns
/// its `version`.
pub fn verify_security_state(key: &SigningKey, signed_b64: &str) -> Result<u64, CryptoError> {
    verify_state(&key.verifying_key(), signed_b64)
}

pub(super) fn verify_state(key: &VerifyingKey, signed_b64: &str) -> Result<u64, CryptoError> {
    let bytes = B64.decode(signed_b64).map_err(|_| CryptoError::Malformed)?;
    let state = verify_sign1(key, &bytes, NS_SECURITY_STATE)?;
    // Other keys (`entityId` in older states) are ignored, as the SDK does.
    match as_map(&state)?.iter().find(|(k, _)| *k == Cbor::text("version")) {
        Some((_, Cbor::Uint(v))) => Ok(*v),
        _ => Err(CryptoError::Malformed),
    }
}

/// Checks a COSE_Sign1's protected header (no `crit`; the key's algorithm and id; signing namespace `ns`; CBOR
/// content), then its signature over `["Signature1", protected, h'', payload]`, and returns the decoded payload.
pub(super) fn verify_sign1(key: &VerifyingKey, bytes: &[u8], ns: i64) -> Result<Cbor, CryptoError> {
    let Cbor::Array(parts) = cbor::decode(bytes)? else { return Err(CryptoError::Malformed) };
    let [Cbor::Bytes(protected), _unprotected, Cbor::Bytes(payload), Cbor::Bytes(signature)] = parts.as_slice() else {
        return Err(CryptoError::Malformed);
    };
    let header = cbor::decode(protected)?;
    let header = as_map(&header)?;
    if get(header, H_CRIT).is_some() {
        return Err(CryptoError::Malformed);
    }
    if get(header, H_ALG) != Some(&key.alg()) || get(header, H_KID) != Some(&Cbor::bytes(key.id.to_vec())) {
        return Err(CryptoError::WrongKey);
    }
    if get(header, H_SIGNING_NAMESPACE) != Some(&int(ns))
        || get(header, H_CONTENT_TYPE) != Some(&Cbor::Uint(CONTENT_CBOR))
    {
        return Err(CryptoError::Malformed);
    }
    let signed = cbor::encode(&Cbor::Array(vec![
        Cbor::text("Signature1"),
        Cbor::bytes(protected.to_vec()),
        Cbor::bytes(vec![]),
        Cbor::bytes(payload.to_vec()),
    ]));
    key.verify_raw(signature, &signed)?;
    cbor::decode(payload)
}
