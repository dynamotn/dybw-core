//! Organization keys, wrapped with RSA-OAEP under the account's public key: EncString type 4 (SHA-1, what the
//! clients write) and type 3 (SHA-256). Types 5 and 6 (OAEP with an HMAC) are not supported, as in both tools.

use super::CryptoError;
use super::enc_string::unknown_type;
use super::key::SymmetricKey;
use crate::ports::{OaepHash, RsaOaep};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use zeroize::Zeroizing;

/// Unwraps an organization key with the account's private key (PKCS#8 DER, from `decrypt_pkcs8`).
pub async fn unwrap_org_key(
    wrapped: &str,
    private_pkcs8: &[u8],
    rsa: &impl RsaOaep,
) -> Result<SymmetricKey, CryptoError> {
    let (ty, body) = wrapped.split_once('.').ok_or(CryptoError::Malformed)?;
    let hash = match ty {
        "4" => OaepHash::Sha1,
        "3" => OaepHash::Sha256,
        _ => return Err(unknown_type(ty)),
    };
    let ct = B64.decode(body).map_err(|_| CryptoError::Malformed)?;
    org_key_from_plaintext(&rsa.decrypt(private_pkcs8, hash, &ct).await?)
}

/// The organization key from RSA-OAEP's plaintext. Not generic, so every port's path is counted in one function.
fn org_key_from_plaintext(key: &[u8]) -> Result<SymmetricKey, CryptoError> {
    // WebKit's RSA-OAEP drops the plaintext's leading zero bytes, so a 64-byte key starting with 0x00 comes back
    // short. A padded COSE key is longer than 64 bytes and starts with its CBOR map, never with a zero.
    if (1..64).contains(&key.len()) {
        let mut full = Zeroizing::new([0u8; 64]);
        full.iter_mut().rev().zip(key.iter().rev()).for_each(|(d, s)| *d = *s);
        return SymmetricKey::from_bytes(&*full);
    }
    SymmetricKey::from_bytes(key)
}

#[cfg(feature = "native")]
pub use native::AwsLcRsa;

#[cfg(feature = "native")]
mod native {
    use crate::ports::{OaepHash, PortError, RsaOaep};
    use aws_lc_rs::rsa::{OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey};
    use zeroize::Zeroizing;

    /// RSA-OAEP decryption with aws-lc-rs (the `rsa` crate is ruled out: RUSTSEC-2023-0071).
    #[derive(Debug, Clone, Copy, Default)]
    pub struct AwsLcRsa;

    impl RsaOaep for AwsLcRsa {
        async fn decrypt(
            &self,
            pkcs8: &[u8],
            hash: OaepHash,
            ciphertext: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, PortError> {
            let key = PrivateDecryptingKey::from_pkcs8(pkcs8)
                .ok()
                .and_then(|k| OaepPrivateDecryptingKey::new(k).ok())
                .ok_or_else(|| PortError("the account's private key cannot be read".into()))?;
            let alg = match hash {
                OaepHash::Sha1 => &OAEP_SHA1_MGF1SHA1,
                OaepHash::Sha256 => &OAEP_SHA256_MGF1SHA256,
            };
            let mut out = Zeroizing::new(vec![0; key.min_output_size()]);
            let n = key
                .decrypt(alg, ciphertext, &mut out, None)
                .map_err(|_| PortError("organization key decryption failed".into()))?
                .len();
            out.truncate(n);
            Ok(out)
        }
    }
}
