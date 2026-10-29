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
    if scheme == "bwss":
        # bwss SymmetricKey::derive("value-mark"), then the MAC half.
        return expand32(user, "bwss value-mark mac")
    # Plugin deriveSubKey("value-fingerprint") over the MAC half of a legacy key.
    return expand32(user[32:], "obsidian-keychain-bitwarden:value-fingerprint")


def main() -> None:
    rows = []
    for account in ["pbkdf2", "org"]:
        user = base64.b64decode(json.loads((VECTORS / "accounts" / f"{account}.json").read_text())["userKey"])
        assert len(user) == 64, "legacy user keys only"
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
