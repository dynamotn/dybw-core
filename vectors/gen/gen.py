#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography", "argon2-cffi", "jsonschema"]
# ///
"""Generator for the conformance vectors. Subcommands: accounts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bwcrypto

VECTORS = Path(__file__).resolve().parent.parent
ACCOUNTS_DIR = VECTORS / "accounts"

# Fake, fixed test values. Seeds are SHA-256("dybw-vectors:<name>"): public,
# never random, never a real credential.
ACCOUNTS = [
    {
        "name": "pbkdf2",
        "email": "pbkdf2@vectors.invalid",
        "password": "vectors-pbkdf2-password",
        "kdf": {"type": "pbkdf2", "iterations": 600000},
        "orgs": [],
    },
    {
        "name": "argon2id",
        "email": "argon2id@vectors.invalid",
        "password": "vectors-argon2id-password",
        "kdf": {"type": "argon2id", "iterations": 3, "memory": 64, "parallelism": 4},
        "orgs": [],
    },
    {
        "name": "org",
        "email": "org@vectors.invalid",
        "password": "vectors-org-password",
        "kdf": {"type": "pbkdf2", "iterations": 600000},
        "orgs": [("org-a", "Org A"), ("org-b", "Org B")],
    },
]


def seed_for(name: str) -> bytes:
    return hashlib.sha256(f"dybw-vectors:{name}".encode()).digest()


def build_account(spec: dict) -> dict:
    seed = seed_for(spec["name"])
    user_key = bwcrypto.derive(seed, 64, "userKey")
    stretched = bwcrypto.stretch(bwcrypto.master_key(spec["password"], spec["email"], spec["kdf"]))
    acc = {
        "name": spec["name"],
        "email": spec["email"],
        "password": spec["password"],
        "kdf": spec["kdf"],
        "seed": bwcrypto.b64(seed),
        "userKey": bwcrypto.b64(user_key),
        "profileKey": bwcrypto.enc_string(
            user_key, stretched, bwcrypto.iv_for(seed, "profileKey")
        ),
    }
    if spec["orgs"]:
        rsa_key = bwcrypto.rsa_key_from_seed(bwcrypto.derive(seed, 32, "rsa"))
        pub = bwcrypto.public_der(rsa_key)
        acc["privateKey"] = bwcrypto.b64(bwcrypto.private_der(rsa_key))
        acc["publicKey"] = bwcrypto.b64(pub)
        acc["organizations"] = []
        for org_id, org_name in spec["orgs"]:
            key = bwcrypto.derive(seed, 64, "org", org_id, "key")
            oaep_seed = bwcrypto.derive(seed, 20, "org", org_id, "oaepSeed")
            acc["organizations"].append(
                {
                    "id": org_id,
                    "name": org_name,
                    "key": bwcrypto.b64(key),
                    "wrapped": bwcrypto.rsa_oaep_wrap(key, pub, sha1=True, seed=oaep_seed),
                }
            )
    return acc


def dump(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def cmd_accounts(_args: argparse.Namespace) -> int:
    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    for spec in ACCOUNTS:
        path = ACCOUNTS_DIR / f"{spec['name']}.json"
        path.write_text(dump(build_account(spec)), encoding="utf-8")
        print(f"wrote {path.relative_to(VECTORS.parent)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("accounts", help="write vectors/accounts/*.json").set_defaults(func=cmd_accounts)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
