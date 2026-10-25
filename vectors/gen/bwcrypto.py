"""Bitwarden crypto for the vectors generator.

Everything here is deterministic: given the same inputs it returns the same
bytes. That is why RSA key generation and OAEP padding are done by hand
(``cryptography`` randomizes both); ``cryptography`` is used only for AES,
HKDF, key serialization, and (in tests) to verify the hand-built OAEP.

Derivation labels used by gen.py (all through ``iv_for`` / ``derive``):
  ("userKey", i)                  64-byte user key, blocks i = 0..3
  ("profileKey",)                 IV of the EncString holding the user key
  ("rsa",)                        seed of the HMAC-DRBG that generates the RSA key
  ("org", <id>, "key", i)         64-byte organization key
  ("org", <id>, "oaepSeed", i)    OAEP seed for wrapping that key
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

PUBLIC_EXPONENT = 65537


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --- keys and EncString type 2 ----------------------------------------------


def master_key(password: str, email: str, kdf: dict) -> bytes:
    """Master key. Salt: email trimmed and lowercased (PBKDF2-SHA256), or its
    SHA-256 (Argon2id), as Bitwarden does. ``kdf["memory"]`` is in MiB."""
    salt = email.strip().lower().encode()
    pw = password.encode()
    if kdf["type"] == "pbkdf2":
        return hashlib.pbkdf2_hmac("sha256", pw, salt, kdf["iterations"], 32)
    if kdf["type"] == "argon2id":
        return hash_secret_raw(
            pw,
            hashlib.sha256(salt).digest(),
            time_cost=kdf["iterations"],
            memory_cost=kdf["memory"] * 1024,
            parallelism=kdf["parallelism"],
            hash_len=32,
            type=Type.ID,
        )
    raise ValueError(f"unknown kdf type: {kdf['type']!r}")


def stretch(mk: bytes) -> bytes:
    """32-byte master key to a 64-byte key: HKDF-Expand 'enc' || 'mac'."""
    enc = HKDFExpand(hashes.SHA256(), 32, b"enc").derive(mk)
    mac = HKDFExpand(hashes.SHA256(), 32, b"mac").derive(mk)
    return enc + mac


def enc_string(plain: bytes, key: bytes, iv: bytes) -> str:
    """Type 2: AES-256-CBC, HMAC-SHA256 over iv || ct. ``2.<iv>|<ct>|<mac>``."""
    padder = padding.PKCS7(128).padder()
    data = padder.update(plain) + padder.finalize()
    enc = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    mac = hmac.new(key[32:], iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def dec_string(s: str, key: bytes) -> bytes:
    """Decrypt a type 2 EncString; the MAC is checked before anything else."""
    head, _, rest = s.partition(".")
    if head != "2":
        raise ValueError(f"unsupported EncString type: {head!r}")
    parts = rest.split("|")
    if len(parts) != 3:
        raise ValueError("malformed EncString")
    iv, ct, mac = (base64.b64decode(p) for p in parts)
    want = hmac.new(key[32:], iv + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(want, mac):
        raise ValueError("MAC mismatch")
    dec = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def iv_for(seed: bytes, *path: str) -> bytes:
    """First 16 bytes of HMAC-SHA256(seed, path joined with NUL)."""
    return hmac.new(seed, "\0".join(path).encode(), hashlib.sha256).digest()[:16]


def derive(seed: bytes, length: int, *path: str) -> bytes:
    """``length`` deterministic bytes: iv_for blocks at path + (index,)."""
    out = b""
    i = 0
    while len(out) < length:
        out += iv_for(seed, *path, str(i))
        i += 1
    return out[:length]


# --- deterministic RSA -------------------------------------------------------


class HmacDrbg:
    """HMAC-DRBG (SHA-256, NIST SP 800-90A, no reseed or additional input)."""

    def __init__(self, seed: bytes) -> None:
        self._k = b"\x00" * 32
        self._v = b"\x01" * 32
        self._update(seed)

    def _hmac(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def _update(self, data: bytes) -> None:
        self._k = self._hmac(self._k, self._v + b"\x00" + data)
        self._v = self._hmac(self._k, self._v)
        if data:
            self._k = self._hmac(self._k, self._v + b"\x01" + data)
            self._v = self._hmac(self._k, self._v)

    def read(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            self._v = self._hmac(self._k, self._v)
            out += self._v
        self._update(b"")
        return out[:n]

    def randbelow(self, bound: int) -> int:
        nbytes = (bound.bit_length() + 7) // 8 + 8  # bias is negligible
        return int.from_bytes(self.read(nbytes), "big") % bound


_SMALL_PRIMES = [p for p in range(3, 2000) if all(p % q for q in range(2, int(p**0.5) + 1))]


def _is_probable_prime(n: int, drbg: HmacDrbg, rounds: int = 64) -> bool:
    """Miller-Rabin with bases drawn from the DRBG."""
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = 2 + drbg.randbelow(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int, drbg: HmacDrbg) -> int:
    while True:
        cand = int.from_bytes(drbg.read(bits // 8), "big")
        cand |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1  # top two bits, odd
        if (cand - 1) % PUBLIC_EXPONENT == 0:
            continue
        if _is_probable_prime(cand, drbg):
            return cand


def rsa_key_from_seed(seed: bytes, bits: int = 2048) -> rsa.RSAPrivateKey:
    """Deterministic RSA key (e = 65537) from a seed. Test-only strength."""
    drbg = HmacDrbg(seed)
    while True:
        p = _gen_prime(bits // 2, drbg)
        q = _gen_prime(bits // 2, drbg)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        if n.bit_length() != bits:
            continue
        d = pow(PUBLIC_EXPONENT, -1, (p - 1) * (q - 1) // _gcd(p - 1, q - 1))
        numbers = rsa.RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=rsa.rsa_crt_dmp1(d, p),
            dmq1=rsa.rsa_crt_dmq1(d, q),
            iqmp=rsa.rsa_crt_iqmp(p, q),
            public_numbers=rsa.RSAPublicNumbers(PUBLIC_EXPONENT, n),
        )
        return numbers.private_key()


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def private_der(key: rsa.RSAPrivateKey) -> bytes:
    """PKCS#8 DER."""
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_der(key: rsa.RSAPrivateKey) -> bytes:
    """SubjectPublicKeyInfo DER."""
    return key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


# --- RSA-OAEP, by hand -------------------------------------------------------


def _mgf1(seed: bytes, length: int, algo: str) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.new(algo, seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def rsa_oaep_wrap(key: bytes, public_der: bytes, sha1: bool, seed: bytes | None = None) -> str:
    """RSA-OAEP (empty label) of ``key``: type 4 with SHA-1, type 3 with SHA-256.

    Padding is built by hand so the seed is a parameter; it defaults to a
    digest of key and public key, which keeps the output deterministic.
    """
    algo = "sha1" if sha1 else "sha256"
    h_len = hashlib.new(algo).digest_size
    pub = serialization.load_der_public_key(public_der)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("not an RSA public key")
    nums = pub.public_numbers()
    k = (nums.n.bit_length() + 7) // 8
    if len(key) > k - 2 * h_len - 2:
        raise ValueError("message too long for OAEP")
    if seed is None:
        seed = hashlib.sha256(b"dybw-oaep-seed\0" + key + public_der).digest()[:h_len]
    if len(seed) != h_len:
        raise ValueError(f"OAEP seed must be {h_len} bytes")
    l_hash = hashlib.new(algo, b"").digest()
    ps = b"\x00" * (k - len(key) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + key
    masked_db = _xor(db, _mgf1(seed, k - h_len - 1, algo))
    masked_seed = _xor(seed, _mgf1(masked_db, h_len, algo))
    em = b"\x00" + masked_seed + masked_db
    ct = pow(int.from_bytes(em, "big"), nums.e, nums.n).to_bytes(k, "big")
    return f"{4 if sha1 else 3}.{b64(ct)}"
