#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Writes vectors/crypto/marks.json: value-mark known answers for bwss and the Obsidian plugin."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

VECTORS = Path(__file__).resolve().parent.parent
TEXTS = ["", "a", "Tiếng Việt 🙂"]


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def expand32(prk: bytes, info: str) -> bytes:
    """HKDF-Expand (RFC 5869) for one 32-byte block."""
    return mac(prk, info.encode() + b"\x01")


def mark_key(user: bytes, scheme: str) -> bytes:
    if len(user) != 64:
        # A padded COSE_Key ends with its 32-byte secret and one 0x01. The plugin's deriveSubKey takes that secret
        # as it is; bwss has no COSE keys, so its scheme uses the same formula on it (owner-approved formula A):
        # PRK = the secret, info "bwss value-mark enc/mac", the MAC half.
        assert user[-1] == 1, "a COSE user key ends with one padding byte"
        secret = user[-33:-1]
        if scheme == "bwss":
            return expand32(secret, "bwss value-mark mac")
        return expand32(secret, "obsidian-keychain-bitwarden:value-fingerprint")
    if scheme == "bwss":
        # bwss SymmetricKey::derive("value-mark"), then the MAC half.
        return expand32(user, "bwss value-mark mac")
    # Plugin deriveSubKey("value-fingerprint") over the MAC half of a legacy key.
    return expand32(user[32:], "obsidian-keychain-bitwarden:value-fingerprint")


def main() -> None:
    rows = []
    for account in ["pbkdf2", "org", "cose"]:
        user = base64.b64decode(json.loads((VECTORS / "accounts" / f"{account}.json").read_text())["userKey"])
        for scheme in ["bwss", "obsidian"]:
            key = mark_key(user, scheme)
            for text in TEXTS:
                mark = mac(key, b"alpha\x00" + text.encode())
                rows.append(
                    {
                        "account": account,
                        "scheme": scheme,
                        "id": "alpha",
                        "text": text,
                        "mark": base64.b64encode(mark).decode(),
                    }
                )
    out = VECTORS / "crypto" / "marks.json"
    out.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
