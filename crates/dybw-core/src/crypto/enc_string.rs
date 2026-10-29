use super::CryptoError;
use super::cose::{ContentFormat, cose_decrypt, cose_encrypt, cose_text_len, parse_cose_key};
use super::key::{SymmetricKey, hmac};
use crate::ports::Random;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type Enc = cbc::Encryptor<aes::Aes256>;
type Dec = cbc::Decryptor<aes::Aes256>;

/// The error for a type prefix the caller does not handle: `UnsupportedType` for a plain decimal, else `Malformed`.
pub(super) fn unknown_type(ty: &str) -> CryptoError {
    match ty.parse::<u8>() {
        Ok(n) if n.to_string() == ty => CryptoError::UnsupportedType(n),
        _ => CryptoError::Malformed,
    }
}

impl SymmetricKey {
    /// Encrypts under the key's own EncString type: `2.iv|ct|mac` for a legacy key, `7.<COSE_Encrypt0>` for a COSE key.
    pub fn encrypt(&self, plain: &[u8], rng: &impl Random) -> Result<String, CryptoError> {
        self.encrypt_as(plain, ContentFormat::OctetStream, rng)
    }

    pub fn encrypt_str(&self, plain: &str, rng: &impl Random) -> Result<String, CryptoError> {
        self.encrypt_as(plain.as_bytes(), ContentFormat::Utf8, rng)
    }

    /// `format` labels type 7 content (authenticated, and checked on decrypt); type 2 carries no label.
    pub fn encrypt_as(&self, plain: &[u8], format: ContentFormat, rng: &impl Random) -> Result<String, CryptoError> {
        match self {
            SymmetricKey::Legacy(k) => {
                let mut iv = [0u8; 16];
                rng.fill(&mut iv)?;
                let (enc, mac) = k.parts();
                let ct = Enc::new(&(*enc).into(), &iv.into()).encrypt_padded_vec::<Pkcs7>(plain);
                let tag = hmac(mac, &[&iv, &ct]);
                Ok(format!("2.{}|{}|{}", B64.encode(iv), B64.encode(&ct), B64.encode(tag)))
            }
            SymmetricKey::Cose(k) => Ok(format!("7.{}", cose_encrypt(k, plain, format, rng)?)),
        }
    }

    /// The length of what `encrypt_str` returns for a text of `len` bytes, without encrypting it (data model §6.4
    /// limits encrypted characters; type 7 strings are longer than type 2 ones).
    pub fn encrypted_str_len(&self, len: usize) -> usize {
        let b64 = |n: usize| n.div_ceil(3) * 4;
        match self {
            SymmetricKey::Legacy(_) => "2.".len() + b64(16) + 1 + b64(16 * (len / 16 + 1)) + 1 + b64(32),
            SymmetricKey::Cose(k) => "7.".len() + b64(cose_text_len(k, len)),
        }
    }

    /// Bytes: a type 7 string must say it holds an octet stream (text, keys and PKCS#8 have their own calls).
    pub fn decrypt(&self, s: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Ok(self.open(s, &[ContentFormat::OctetStream])?.0)
    }

    /// The account's private key (PKCS#8 DER); a type 7 string must be labelled PKCS#8, as the plugin requires.
    pub fn decrypt_pkcs8(&self, s: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Ok(self.open(s, &[ContentFormat::Pkcs8])?.0)
    }

    /// Dispatches on the type prefix: `2.` for a legacy key, `7.` for a COSE key; a value of the other type is
    /// `WrongKey`, any other number `UnsupportedType`. A type 7 value must hold one of the `expected` formats.
    fn open(
        &self,
        s: &str,
        expected: &[ContentFormat],
    ) -> Result<(Zeroizing<Vec<u8>>, Option<ContentFormat>), CryptoError> {
        let (ty, rest) = s.split_once('.').ok_or(CryptoError::Malformed)?;
        // Exact decimal strings only: "02" and "+2" are not type 2 (bwss matches the string "2").
        match (ty, self) {
            ("2", SymmetricKey::Legacy(k)) => Ok((Self::decrypt2(k.parts(), rest)?, None)),
            ("7", SymmetricKey::Cose(k)) => {
                let (plain, format) = cose_decrypt(k, rest)?;
                if !expected.contains(&format) {
                    return Err(CryptoError::Malformed);
                }
                Ok((plain, Some(format)))
            }
            ("2" | "7", _) => Err(CryptoError::WrongKey),
            _ => Err(unknown_type(ty)),
        }
    }

    /// The MAC is checked in constant time before anything is decrypted.
    #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
    fn decrypt2(parts: (&[u8; 32], &[u8; 32]), rest: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut fields = rest.split('|');
        let (Some(iv), Some(ct), Some(mac), None) = (fields.next(), fields.next(), fields.next(), fields.next()) else {
            return Err(CryptoError::Malformed);
        };
        let dec = |s: &str| B64.decode(s).map_err(|_| CryptoError::Malformed);
        let (iv, ct, mac) = (dec(iv)?, dec(ct)?, dec(mac)?);
        let iv: [u8; 16] = iv.try_into().map_err(|_| CryptoError::Malformed)?;
        if mac.len() != 32 || ct.is_empty() || ct.len() % 16 != 0 {
            return Err(CryptoError::Malformed);
        }
        let (enc, mkey) = parts;
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(mkey).expect("HMAC accepts any key length");
        m.update(&iv);
        m.update(&ct);
        m.verify_slice(&mac).map_err(|_| CryptoError::BadMac)?;
        Dec::new(&(*enc).into(), &iv.into())
            .decrypt_padded_vec::<Pkcs7>(&ct)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Decrypt)
    }

    /// Non-UTF-8 plaintext is `Decrypt`; validated in place so no unwiped copy lands in an error.
    pub fn decrypt_str(&self, s: &str) -> Result<Zeroizing<String>, CryptoError> {
        let (bytes, _) = self.open(s, &[ContentFormat::Utf8])?;
        std::str::from_utf8(&bytes).map(|t| Zeroizing::new(t.to_owned())).map_err(|_| CryptoError::Decrypt)
    }

    /// Decrypts a wrapped key (a user key or an item key); a type 7 value says whether it holds a COSE key.
    pub fn decrypt_key(&self, s: &str) -> Result<SymmetricKey, CryptoError> {
        let (bytes, format) = self.open(s, &[ContentFormat::LegacyKey, ContentFormat::CoseKey])?;
        match format {
            Some(ContentFormat::CoseKey) => Ok(SymmetricKey::Cose(parse_cose_key(&bytes)?)),
            _ => SymmetricKey::from_bytes(&bytes),
        }
    }
}
