//! The two AEADs behind EncString type 7, both with a 256-bit key and a 192-bit nonce and a 16-byte tag after the
//! ciphertext. Keys and nonces are fixed-size arrays, so a 16-byte key can never select AES-128.
//!
//! - XAES-256-GCM (<https://c2sp.org/XAES-256-GCM>): AES-256-GCM under a per-nonce key from a CMAC-based counter KDF
//!   over `nonce[0..12]`; `nonce[12..24]` is the GCM nonce.
//! - XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha).

use super::CryptoError;
use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

/// The XAES-256-GCM key for one nonce prefix (C2SP: SP 800-108 counter KDF with CMAC-AES256, subkey K1 only).
fn xaes_derive(key: &[u8; 32], prefix: &[u8]) -> Zeroizing<[u8; 32]> {
    let aes = Aes256::new(&(*key).into());
    let mut l = [0u8; 16].into();
    aes.encrypt_block(&mut l);
    // K1 = L << 1 in GF(2^128), reduced by x^128 + x^7 + x^2 + x + 1 when the top bit falls off.
    let l = u128::from_be_bytes(l.into());
    let k1 = (l << 1) ^ if l >> 127 == 1 { 0x87 } else { 0 };
    let mut derived = Zeroizing::new([0u8; 32]);
    for (i, out) in derived.as_chunks_mut::<16>().0.iter_mut().enumerate() {
        let mut m = [0u8; 16];
        let (h, n) = m.split_at_mut(4);
        h.copy_from_slice(&[0, i as u8 + 1, b'X', 0]);
        n.copy_from_slice(prefix);
        let mut block = (u128::from_be_bytes(m) ^ k1).to_be_bytes().into();
        aes.encrypt_block(&mut block);
        out.copy_from_slice(&block);
    }
    derived
}

fn xaes_cipher(key: &[u8; 32], nonce: &[u8; 24]) -> (Aes256Gcm, [u8; 12]) {
    let (prefix, iv) = nonce.split_at(12);
    let derived = xaes_derive(key, prefix);
    let mut gcm_nonce = [0u8; 12];
    gcm_nonce.copy_from_slice(iv);
    (Aes256Gcm::new(&(*derived).into()), gcm_nonce)
}

pub fn xaes256gcm_encrypt(key: &[u8; 32], nonce: &[u8; 24], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (cipher, iv) = xaes_cipher(key, nonce);
    cipher.encrypt(&iv.into(), Payload { msg: data, aad }).map_err(|_| CryptoError::Malformed)
}

pub fn xaes256gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    data: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let (cipher, iv) = xaes_cipher(key, nonce);
    cipher.decrypt(&iv.into(), Payload { msg: data, aad }).map(Zeroizing::new).map_err(|_| CryptoError::BadMac)
}

pub fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    cipher.encrypt(&(*nonce).into(), Payload { msg: data, aad }).map_err(|_| CryptoError::Malformed)
}

pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    data: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    cipher.decrypt(&(*nonce).into(), Payload { msg: data, aad }).map(Zeroizing::new).map_err(|_| CryptoError::BadMac)
}
