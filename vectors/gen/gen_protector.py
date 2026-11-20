#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography", "argon2-cffi"]
# ///
"""Writes vectors/crypto/protector.json: known answers for ADR 0006's local unlock protectors (`profile::protector`).

An independent reference of the format: Argon2id (argon2-cffi) or 32 hardware bytes as the KEK, HKDF-SHA256
(`cryptography`) with the binding as salt and `dybw-unlock:<protector>` as info, and the user key wrapped as an
EncString of type 2 (`bwcrypto.enc_string`). Deterministic: every salt, IV and hardware byte is derived from a fixed
seed.

    uv run vectors/gen/gen_protector.py            # rewrite the file
    uv run vectors/gen/gen_protector.py --check    # exit 1 when the file is stale
"""

from __future__ import annotations

import base64
import json
import struct
import sys
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bwcrypto

VECTORS = Path(__file__).resolve().parent.parent
OUT = VECTORS / "crypto" / "protector.json"
SEED = b"dybw-vectors:protector"
BINDING = {"deviceId": "4b1c7e2a-9d3f-4e5a-8b6c-0d1e2f3a4b5c", "machine": "564D4F2A-1B2C-4D3E-8F40-VECTORS00001"}
OTHER_DEVICE = {**BINDING, "deviceId": "0a0b0c0d-0e0f-4a1b-8c2d-3e4f5a6b7c8d"}
OTHER_MACHINE = {**BINDING, "machine": "0123456789abcdef0123456789abcdef"}
PIN = "2468"
HARDWARE = bwcrypto.derive(SEED, 32, "hardware")
OTHER_HARDWARE = bwcrypto.derive(SEED, 32, "other-hardware")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def accounts() -> dict:
    """`org` has a legacy user key (its private key wrapped here as type 2); the two COSE accounts are the SDK's."""
    org = json.loads((VECTORS / "accounts" / "org.json").read_text())
    org_user = base64.b64decode(org["userKey"])
    wrapped = bwcrypto.enc_string(base64.b64decode(org["privateKey"]), org_user, bwcrypto.iv_for(SEED, "org-pk"))
    out = {"org": {"userKey": org["userKey"], "sync": {"profile": {"privateKey": wrapped}}}}
    for a in json.loads((VECTORS / "crypto" / "cose-vectors.json").read_text())["accounts"]:
        out[a["name"]] = {"userKey": a["userKey"], "sync": {"profile": {"privateKey": a["privateKey"]["wrapped"]}}}
    out["no-private-key"] = {"userKey": None, "sync": {"profile": {}}}
    return out


def ikm(kdf: dict, kek: dict) -> bytes:
    if kdf["type"] == "hardware":
        return base64.b64decode(kek["hardware"])
    return hash_secret_raw(
        kek["secret"].encode(),
        base64.b64decode(kdf["salt"]),
        time_cost=kdf["iterations"],
        memory_cost=kdf["memory"] * 1024,
        parallelism=kdf["parallelism"],
        hash_len=32,
        type=Type.ID,
    )


def wrapping_key(protector: str, kdf: dict, kek: dict, binding: dict) -> bytes:
    salt = b"".join(struct.pack(">I", len(f.encode())) + f.encode() for f in (binding["deviceId"], binding["machine"]))
    return HKDF(hashes.SHA256(), 64, salt, f"dybw-unlock:{protector}".encode()).derive(ikm(kdf, kek))


def argon(label: str, iterations: int = 3, memory: int = 64, parallelism: int = 1) -> dict:
    salt = b64(bwcrypto.derive(SEED, 32, label, "salt"))
    return {"type": "argon2id", "iterations": iterations, "memory": memory, "parallelism": parallelism, "salt": salt}


def blob(label: str, protector: str, kdf: dict, kek: dict, user_key: str, attempts: int = 0) -> dict:
    key = wrapping_key(protector, kdf, kek, BINDING)
    wrapped = bwcrypto.enc_string(base64.b64decode(user_key), key, bwcrypto.iv_for(SEED, label, "iv"))
    return {
        "version": 1,
        "protector": protector,
        "deviceId": BINDING["deviceId"],
        "machine": BINDING["machine"],
        "kdf": kdf,
        "wrappedKey": wrapped,
        "attempts": attempts,
    }


def text(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"))


def build() -> str:
    acc = accounts()
    pin = {"secret": PIN}
    hw = {"hardware": b64(HARDWARE)}
    pin_blob = blob("pin-org", "pin", argon("pin-org"), pin, acc["org"]["userKey"])
    login_blob = blob("login-cose", "login", argon("login-cose", 4, 128, 2), {"secret": "login password ✓"},
                      acc["xaes-256-gcm"]["userKey"])
    bio = blob("biometric-cose", "biometric", {"type": "hardware"}, hw, acc["xaes-256-gcm"]["userKey"])
    bio_org = blob("biometric-org", "biometric", {"type": "hardware"}, hw, acc["org"]["userKey"], attempts=3)

    def row(about, raw, kek, account, binding=BINDING, error=None, attempts_after=None):
        r = {"about": about, "raw": raw if isinstance(raw, str) else text(raw), "kek": kek, "binding": binding,
             "account": account}
        if error:
            r["error"] = error
        if attempts_after is not None:
            r["attemptsAfter"] = attempts_after
        return r

    def edit(base, **changes):
        return {**base, **changes}

    def edit_kdf(**changes):
        return edit(pin_blob, kdf={**pin_blob["kdf"], **changes})

    unwraps = [
        row("pin over the floor parameters, legacy user key", pin_blob, pin, "org", attempts_after=0),
        row("login password, stronger parameters, COSE user key", login_blob, {"secret": "login password ✓"},
            "xaes-256-gcm", attempts_after=0),
        row("biometric hardware bytes, COSE user key", bio, hw, "xaes-256-gcm", attempts_after=0),
        row("a success resets the attempt count", bio_org, hw, "org", attempts_after=0),
    ]
    errors = [
        row("not JSON", "{", hw, "org", error="format"),
        row("unknown version", edit(bio, version=2), hw, "xaes-256-gcm", error="format"),
        row("unknown field", edit(bio, extra=1), hw, "xaes-256-gcm", error="format"),
        row("unknown protector", edit(bio, protector="face"), hw, "xaes-256-gcm", error="format"),
        row("unknown KDF", edit(bio, kdf={"type": "pbkdf2"}), hw, "xaes-256-gcm", error="format"),
        row("missing attempts", {k: v for k, v in bio.items() if k != "attempts"}, hw, "xaes-256-gcm",
            error="format"),
        row("empty device id", edit(bio, deviceId=""), hw, "xaes-256-gcm", binding={**BINDING, "deviceId": ""},
            error="format"),
        row("empty machine fingerprint", edit(bio, machine=""), hw, "xaes-256-gcm",
            binding={**BINDING, "machine": ""}, error="format"),
        row("salt of 16 bytes", edit_kdf(salt=b64(bytes(16))), pin, "org", error="format"),
        row("wrapped key not an EncString", edit(bio, wrappedKey="not an encstring"), hw, "xaes-256-gcm",
            error="format"),
        row("wrapped key of type 7", edit(bio, wrappedKey="7.AAAA"), hw, "xaes-256-gcm", error="format"),
        row("memory 63 MiB", edit_kdf(memory=63), pin, "org", error="weak-kdf"),
        row("iterations 2", edit_kdf(iterations=2), pin, "org", error="weak-kdf"),
        row("parallelism 0", edit_kdf(parallelism=0), pin, "org", error="weak-kdf"),
        row("memory above 1 GiB", edit_kdf(memory=1025), pin, "org", error="weak-kdf"),
        row("iterations above 10", edit_kdf(iterations=11), pin, "org", error="weak-kdf"),
        row("another device id", bio, hw, "xaes-256-gcm", binding=OTHER_DEVICE, error="binding"),
        row("another machine", pin_blob, pin, "org", binding=OTHER_MACHINE, error="binding"),
        row("five failed attempts", edit(bio, attempts=5), hw, "xaes-256-gcm", error="invalidated"),
        row("a secret for a hardware protector", bio, pin, "xaes-256-gcm", error="kek"),
        row("hardware bytes for a secret protector", pin_blob, hw, "org", error="kek"),
        row("wrong PIN", pin_blob, {"secret": "1357"}, "org", error="wrong", attempts_after=1),
        row("wrong hardware bytes, the fifth failure", edit(bio, attempts=4), {"hardware": b64(OTHER_HARDWARE)},
            "xaes-256-gcm", error="wrong", attempts_after=5),
        row("device id edited to this device's: the binding is authenticated", edit(bio, **OTHER_DEVICE), hw,
            "xaes-256-gcm", binding=OTHER_DEVICE, error="wrong", attempts_after=1),
        row("protector renamed: the name is authenticated", edit(bio, protector="login"), hw, "xaes-256-gcm",
            error="wrong", attempts_after=1),
        row("rotated user key: another account's private key", bio, hw, "xchacha20-poly1305", error="stale",
            attempts_after=0),
        row("legacy key against a COSE account", edit(bio_org, attempts=0), hw, "xaes-256-gcm", error="stale",
            attempts_after=0),
        row("no private key to check against", bio, hw, "no-private-key", error="stale", attempts_after=0),
    ]
    doc = {
        "about": "ADR 0006 protector blobs (profile::protector), written by vectors/gen/gen_protector.py. `raw` is the "
        "stored blob text; `kek` is a UTF-8 `secret` or base64 `hardware` bytes; `account` names an entry of "
        "`accounts`, whose `sync` is what the key is checked against and whose `userKey` an unwrap returns. `error` is "
        "ProtectorError::code; `attemptsAfter` is the blob's count after the call.",
        "accounts": acc,
        "unwrap": unwraps,
        "errors": errors,
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def main() -> None:
    out = build()
    if sys.argv[1:] == ["--check"]:
        if OUT.read_text(encoding="utf-8") != out:
            print(f"stale: {OUT}")
            sys.exit(1)
        return
    OUT.write_text(out, encoding="utf-8")


if __name__ == "__main__":
    main()
