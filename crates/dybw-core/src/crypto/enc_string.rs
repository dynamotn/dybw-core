use super::CryptoError;
use super::key::{SymmetricKey, hmac};
use crate::ports::Random;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type Enc = cbc::Encryptor<aes::Aes256>;
type Dec = cbc::Decryptor<aes::Aes256>;

impl SymmetricKey {
    /// Encrypts into a type 2 string `2.iv|ct|mac` under a fresh random IV.
    pub fn encrypt(&self, plain: &[u8], rng: &impl Random) -> Result<String, CryptoError> {
        let mut iv = [0u8; 16];
        rng.fill(&mut iv)?;
        let (enc, mac) = self.parts();
        let ct = Enc::new(&(*enc).into(), &iv.into()).encrypt_padded_vec::<Pkcs7>(plain);
        let tag = hmac(mac, &[&iv, &ct]);
        Ok(format!("2.{}|{}|{}", B64.encode(iv), B64.encode(&ct), B64.encode(tag)))
    }

    pub fn encrypt_str(&self, plain: &str, rng: &impl Random) -> Result<String, CryptoError> {
        self.encrypt(plain.as_bytes(), rng)
    }

    /// Dispatches on the type prefix: `2.` here, anything else is unsupported.
    pub fn decrypt(&self, s: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let (ty, rest) = s.split_once('.').ok_or(CryptoError::Malformed)?;
        // Exact decimal strings only: "02" and "+2" are not type 2 (bwss matches the string "2").
        if ty == "2" {
            return self.decrypt2(rest);
        }
        match ty.parse::<u8>() {
            Ok(n) if n.to_string() == ty => Err(CryptoError::UnsupportedType(n)),
            _ => Err(CryptoError::Malformed),
        }
    }

    /// The MAC is checked in constant time before anything is decrypted.
    #[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
    fn decrypt2(&self, rest: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut parts = rest.split('|');
        let (Some(iv), Some(ct), Some(mac), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return Err(CryptoError::Malformed);
        };
        let dec = |s: &str| B64.decode(s).map_err(|_| CryptoError::Malformed);
        let (iv, ct, mac) = (dec(iv)?, dec(ct)?, dec(mac)?);
        let iv: [u8; 16] = iv.try_into().map_err(|_| CryptoError::Malformed)?;
        if mac.len() != 32 || ct.is_empty() || ct.len() % 16 != 0 {
            return Err(CryptoError::Malformed);
        }
        let (enc, mkey) = self.parts();
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
        let bytes = self.decrypt(s)?;
        std::str::from_utf8(&bytes).map(|t| Zeroizing::new(t.to_owned())).map_err(|_| CryptoError::Decrypt)
    }

    /// Decrypts a wrapped key (a user key or an item key).
    pub fn decrypt_key(&self, s: &str) -> Result<SymmetricKey, CryptoError> {
        SymmetricKey::from_bytes(&self.decrypt(s)?)
    }
}
