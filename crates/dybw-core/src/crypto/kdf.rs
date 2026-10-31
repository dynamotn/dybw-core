use super::CryptoError;
use crate::ports::{Argon2Input, KdfRunner};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The 32-byte key derived from the master password.
pub type MasterKey = Zeroizing<[u8; 32]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfParams {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}

impl KdfParams {
    /// Lower bounds stop a hostile server downgrading the KDF; upper bounds stop it pinning the CPU or memory.
    pub fn validate(&self) -> Result<(), CryptoError> {
        let bad = |what: &str, v: u32| Err(CryptoError::Kdf(format!("{what} {v} out of range")));
        match *self {
            KdfParams::Pbkdf2 { iterations } if !(5_000..=2_000_000).contains(&iterations) => {
                bad("PBKDF2 iterations", iterations)
            }
            KdfParams::Argon2id { iterations, .. } if !(2..=10).contains(&iterations) => {
                bad("Argon2 iterations", iterations)
            }
            KdfParams::Argon2id { memory_mib, .. } if !(16..=1024).contains(&memory_mib) => {
                bad("Argon2 memory", memory_mib)
            }
            KdfParams::Argon2id { parallelism, .. } if !(1..=16).contains(&parallelism) => {
                bad("Argon2 parallelism", parallelism)
            }
            _ => Ok(()),
        }
    }

    /// ADR 0017's floors for a new pin: PBKDF2 600,000 iterations; Argon2id 64 MiB, 3 iterations, 1 lane.
    pub fn meets_floors(&self) -> bool {
        match *self {
            KdfParams::Pbkdf2 { iterations } => iterations >= 600_000,
            KdfParams::Argon2id { iterations, memory_mib, parallelism } => {
                iterations >= 3 && memory_mib >= 64 && parallelism >= 1
            }
        }
    }

    /// Weaker than the pinned parameters: of the same type, any parameter lower; of another type, unless these
    /// meet the floors.
    pub fn weaker_than(&self, pinned: &KdfParams) -> bool {
        match (*self, *pinned) {
            (KdfParams::Pbkdf2 { iterations: a }, KdfParams::Pbkdf2 { iterations: b }) => a < b,
            (
                KdfParams::Argon2id { iterations: ai, memory_mib: am, parallelism: ap },
                KdfParams::Argon2id { iterations: bi, memory_mib: bm, parallelism: bp },
            ) => ai < bi || am < bm || ap < bp,
            _ => !self.meets_floors(),
        }
    }
}

/// Validates first; the salt is the email trimmed and lowercased (SHA-256 of it for Argon2id).
pub async fn derive_master_key(
    password: &str,
    email: &str,
    kdf: KdfParams,
    runner: &impl KdfRunner,
) -> Result<MasterKey, CryptoError> {
    kdf.validate()?;
    let salt = email.trim().to_lowercase();
    match kdf {
        KdfParams::Pbkdf2 { iterations } => {
            let mut out = Zeroizing::new([0u8; 32]);
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations, out.as_mut());
            Ok(out)
        }
        KdfParams::Argon2id { iterations, memory_mib, parallelism } => runner
            .argon2id(Argon2Input {
                password: Zeroizing::new(password.as_bytes().to_vec()),
                salt: Sha256::digest(salt.as_bytes()).into(),
                iterations,
                memory_kib: memory_mib * 1024,
                parallelism,
            })
            .await
            .map_err(|e| CryptoError::Kdf(e.0)),
    }
}

/// The hash a server stores for password logins.
pub fn hash_master_password(master: &MasterKey, password: &str) -> String {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(master.as_ref(), password.as_bytes(), 1, &mut out);
    B64.encode(out)
}

/// Argon2id with the `argon2` crate (version 0x13, 32-byte output).
#[cfg(feature = "native")]
pub struct NativeArgon2;

#[cfg(feature = "native")]
impl KdfRunner for NativeArgon2 {
    async fn argon2id(&self, i: Argon2Input) -> Result<Zeroizing<[u8; 32]>, crate::ports::PortError> {
        let fail = |e: argon2::Error| crate::ports::PortError(e.to_string());
        let params = argon2::Params::new(i.memory_kib, i.iterations, i.parallelism, Some(32)).map_err(fail)?;
        let mut out = Zeroizing::new([0u8; 32]);
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(&i.password, &i.salt, out.as_mut())
            .map_err(fail)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::KdfParams::{self, Argon2id, Pbkdf2};

    fn argon(iterations: u32, memory_mib: u32, parallelism: u32) -> KdfParams {
        Argon2id { iterations, memory_mib, parallelism }
    }

    #[test]
    fn floors() {
        assert!(Pbkdf2 { iterations: 600_000 }.meets_floors());
        assert!(!Pbkdf2 { iterations: 599_999 }.meets_floors());
        assert!(argon(3, 64, 1).meets_floors());
        assert!(!argon(2, 64, 1).meets_floors());
        assert!(!argon(3, 63, 1).meets_floors());
        assert!(!argon(3, 64, 0).meets_floors());
    }

    #[test]
    fn weaker_than_the_pin() {
        let (p, a) = (Pbkdf2 { iterations: 700_000 }, argon(3, 64, 4));
        assert!(!p.weaker_than(&p));
        assert!(!a.weaker_than(&a));
        assert!(Pbkdf2 { iterations: 699_999 }.weaker_than(&p));
        assert!(!Pbkdf2 { iterations: 700_001 }.weaker_than(&p));
        assert!(argon(2, 64, 4).weaker_than(&a));
        assert!(argon(3, 63, 4).weaker_than(&a));
        assert!(argon(3, 64, 3).weaker_than(&a));
        assert!(!argon(4, 128, 8).weaker_than(&a));
        // A type change is weaker unless the new parameters meet the floors.
        assert!(Pbkdf2 { iterations: 5_000 }.weaker_than(&a));
        assert!(argon(2, 16, 1).weaker_than(&p));
        assert!(!Pbkdf2 { iterations: 600_000 }.weaker_than(&a));
        assert!(!a.weaker_than(&p));
    }
}
