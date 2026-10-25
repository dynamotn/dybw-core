#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography", "argon2-cffi", "jsonschema"]
# ///
"""Generator for the conformance vectors. Subcommands: accounts, build, check."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

import jsonschema
from referencing import Registry, Resource

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bwcrypto

VECTORS = Path(__file__).resolve().parent.parent
ACCOUNTS_DIR = VECTORS / "accounts"
SRC_DIR = VECTORS / "src"
OUT_DIR = VECTORS / "generated"
SCHEMA_DIR = VECTORS / "schema"
GENERATOR = "dybw-vectors-gen 1"

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


def cmd_accounts(_args: argparse.Namespace) -> int:
    ACCOUNTS_DIR.mkdir(parents=True, exist_ok=True)
    for spec in ACCOUNTS:
        path = ACCOUNTS_DIR / f"{spec['name']}.json"
        path.write_text(dump(build_account(spec)), encoding="utf-8")
        print(f"wrote {path.relative_to(VECTORS.parent)}")
    return 0


# --- scenario build ----------------------------------------------------------
#
# Derivation labels (all through bwcrypto.iv_for / derive, seed = account seed;
# <sid> scenario id, <ns> namespace, <cid> cipher id after {ns} expansion):
#   iv_for(seed, sid, ns, cid, <jsonpath>)            IV of one string, for
#       example "name", "login.password", "fields[2].name",
#       "login.passwordHistory[0].password"
#   iv_for(seed, sid, ns, cid, "key")                 IV of the wrapped item key
#   derive(seed, 64, sid, ns, cid, "itemKey")         the 64-byte item key
# A cipher in operation.fresh with the id of a cipher in ciphers[] that has itemKey
# reuses that cipher's item key (re-wrapped with a fresh IV). Otherwise it uses the
# same labels with an extra "fresh"
# component right after <cid> (before <jsonpath>, "key" and "itemKey").


class GenError(Exception):
    """A source, schema or account problem, reported with its file name."""


def _registry() -> Registry:
    reg = Registry()
    for name in ("source.schema.json", "scenario.schema.json"):
        doc = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
        reg = reg.with_resource(doc["$id"], Resource.from_contents(doc))
    return reg


def _validator(name: str) -> jsonschema.Draft202012Validator:
    doc = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(doc, registry=_registry())


def _validate(validator: jsonschema.Draft202012Validator, obj: dict, label: str) -> None:
    err = jsonschema.exceptions.best_match(validator.iter_errors(obj))
    if err is not None:
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        raise GenError(f"{label}: {where}: {err.message}")


def load_account(name: str, accounts_dir: Path = ACCOUNTS_DIR) -> dict:
    path = accounts_dir / f"{name}.json"
    if not path.is_file():
        raise GenError(f"account not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _owner_key(account: dict, org_id: str | None) -> bytes:
    if org_id is None:
        return base64.b64decode(account["userKey"])
    for org in account.get("organizations", []):
        if org["id"] == org_id:
            return base64.b64decode(org["key"])
    raise GenError(f"account {account['name']!r} has no organization {org_id!r}")


def expand_ns(value, ns: str):
    """Replace the literal ``{ns}`` in every string, and in every dict key."""
    if isinstance(value, str):
        return value.replace("{ns}", ns)
    if isinstance(value, list):
        return [expand_ns(v, ns) for v in value]
    if isinstance(value, dict):
        return {expand_ns(k, ns): expand_ns(v, ns) for k, v in value.items()}
    return value


def _pascal(key: str) -> str:
    return key[:1].upper() + key[1:]


class _Encryptor:
    def __init__(self, seed: bytes, sid: str, ns: str, cid: str, fresh: bool) -> None:
        self.seed = seed
        self.base = (sid, ns, cid) + (("fresh",) if fresh else ())
        self.key = b""

    def enc(self, plain: str | None, path: str) -> str | None:
        if plain is None:
            return None
        iv = bwcrypto.iv_for(self.seed, *self.base, path)
        return bwcrypto.enc_string(plain.encode("utf-8"), self.key, iv)


def encrypt_cipher(
    src: dict, account: dict, sid: str, ns: str, fresh: bool = False, same_as: dict | None = None
) -> dict:
    """Server-shaped cipher from a plaintext one (``{ns}`` already expanded)."""
    seed = base64.b64decode(account["seed"])
    owner = _owner_key(account, src.get("organizationId"))
    e = _Encryptor(seed, sid, ns, src["id"], fresh)
    out: dict = {"id": src["id"], "type": src["type"]}
    for k in ("folderId", "organizationId"):
        if k in src:
            out[k] = src[k]
    if src.get("itemKey"):
        if same_as is not None and same_as.get("itemKey"):
            # a server keeps the item key across edits: reuse the original's
            item_key = bwcrypto.derive(seed, 64, sid, ns, src["id"], "itemKey")
        else:
            item_key = bwcrypto.derive(seed, 64, *e.base, "itemKey")
        out["key"] = bwcrypto.enc_string(item_key, owner, bwcrypto.iv_for(seed, *e.base, "key"))
        e.key = item_key
    else:
        e.key = owner
    out["name"] = e.enc(src["name"], "name")
    if "notes" in src:
        out["notes"] = e.enc(src["notes"], "notes")
    history = None
    if "login" in src:
        lg = src["login"]
        if lg is None:
            out["login"] = None
        else:
            out["login"] = {
                "username": e.enc(lg["username"], "login.username"),
                "password": e.enc(lg["password"], "login.password"),
                "uris": [
                    {"uri": e.enc(u, f"login.uris[{i}].uri"), "match": None}
                    for i, u in enumerate(lg["uris"])
                ],
                "totp": e.enc(lg["totp"], "login.totp"),
            }
            history = [
                {
                    "password": e.enc(h["password"], f"login.passwordHistory[{i}].password"),
                    "lastUsedDate": h["lastUsedDate"],
                }
                for i, h in enumerate(lg["passwordHistory"])
            ]
    if src["type"] == 2:
        out["secureNote"] = {"type": 0}
    if "fields" in src:
        fields = src["fields"]
        out["fields"] = (
            None
            if fields is None
            else [
                {
                    "name": e.enc(f["name"], f"fields[{i}].name"),
                    "value": e.enc(f["value"], f"fields[{i}].value"),
                    "type": f["type"],
                }
                for i, f in enumerate(fields)
            ]
        )
    if history is not None:
        out["passwordHistory"] = history
    for k in ("creationDate", "revisionDate", "deletedDate", "edit", "viewPassword"):
        if k in src:
            out[k] = src[k]
    return _apply_case(out, src.get("pascalCase", False), src.get("extra", {}))


def _apply_case(cipher: dict, pascal: bool, extra: dict) -> dict:
    def conv(v):
        if isinstance(v, dict):
            return {_pascal(k): conv(x) for k, x in v.items()}
        if isinstance(v, list):
            return [conv(x) for x in v]
        return v

    out = conv(cipher) if pascal else cipher
    return {**out, **extra}


def render_scenario(src: dict, ns: str, account: dict) -> dict:
    """The generated scenario for one namespace of a source."""
    sid = src["id"]
    body = expand_ns({k: v for k, v in src.items() if k not in ("id", "sections")}, ns)
    out: dict = {"id": sid, "spec": body["spec"], "sections": src["sections"]}
    out["account"] = body["account"]
    out["namespace"] = ns
    out["generator"] = GENERATOR
    if "options" in body:
        out["options"] = body["options"]
    if "local" in body:
        out["local"] = body["local"]
    if "device" in body:
        out["device"] = body["device"]
    ids = [c["id"] for c in body["ciphers"]]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise GenError(f"duplicate cipher ids: {', '.join(dupes)}")
    out["ciphers"] = [encrypt_cipher(c, account, sid, ns) for c in body["ciphers"]]
    if "operation" in body:
        op = dict(body["operation"])
        if "fresh" in op:
            original = next((c for c in body["ciphers"] if c["id"] == op["fresh"]["id"]), None)
            op["fresh"] = encrypt_cipher(op["fresh"], account, sid, ns, True, original)
        out["operation"] = op
    out["expect"] = body["expect"]
    return out


def dump(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def render_all(
    src_dir: Path = SRC_DIR, accounts_dir: Path = ACCOUNTS_DIR
) -> dict[str, str]:
    """Every generated file as ``{"<ns>/<id>.json": text}``. Validates both ends."""
    source_v = _validator("source.schema.json")
    scenario_v = _validator("scenario.schema.json")
    files: dict[str, str] = {}
    for path in sorted(src_dir.rglob("*.json")) if src_dir.is_dir() else []:
        rel = path.relative_to(src_dir).with_suffix("").as_posix()
        try:
            src = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise GenError(f"{path}: {exc}") from exc
        _validate(source_v, src, str(path))
        if src["id"] != rel:
            raise GenError(f"{path}: id {src['id']!r} does not match its path {rel!r}")
        account = load_account(src["account"], accounts_dir)
        for ns in src["namespaces"]:
            label = f"{path} [{ns}]"
            try:
                scenario = render_scenario(src, ns, account)
            except GenError as exc:
                raise GenError(f"{label}: {exc}") from exc
            _validate(scenario_v, scenario, label)
            files[f"{ns}/{src['id']}.json"] = dump(scenario)
    return files


NAMESPACES = ("bwss", "obsidian")


def _walk_json(root: Path):
    """Regular ``*.json`` files below ``root``; symlinks are never followed."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for name in filenames:
            path = Path(dirpath) / name
            if name.endswith(".json") and not path.is_symlink():
                yield path


def _is_ours(path: Path) -> bool:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    gen_tag = doc.get("generator") if isinstance(doc, dict) else None
    return isinstance(gen_tag, str) and gen_tag.startswith("dybw-vectors-gen")


def _owned(out_root: Path) -> set[str]:
    """Generated files below ``out_root/<ns>/``. Refuses a directory that holds
    ``*.json`` files outside those subtrees (a wrong ``--out``)."""
    if not out_root.is_dir():
        return set()
    ns_roots = {out_root / ns for ns in NAMESPACES}
    for ns_root in ns_roots:
        if ns_root.is_symlink():
            raise GenError(f"{ns_root} is a symlink")
    foreign = []
    for dirpath, dirnames, filenames in os.walk(out_root, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = [
            d for d in dirnames if (here / d) not in ns_roots and not (here / d).is_symlink()
        ]
        foreign += [here / n for n in filenames if n.endswith(".json")]
    if foreign:
        raise GenError(
            f"refusing to use {out_root} as output: it holds JSON files outside "
            f"{'/'.join(NAMESPACES)} subtrees, for example {foreign[0]}"
        )
    owned = set()
    for ns_root in ns_roots:
        if ns_root.is_dir():
            owned |= {
                p.relative_to(out_root).as_posix() for p in _walk_json(ns_root) if _is_ours(p)
            }
    return owned


def build(src_dir: Path = SRC_DIR, out_dir: Path = OUT_DIR, accounts_dir: Path = ACCOUNTS_DIR):
    """Write every generated file and remove stale generated files under
    ``out_dir/<ns>/`` (only files whose ``generator`` marks them as ours)."""
    files = render_all(src_dir, accounts_dir)
    out_root = out_dir.resolve()
    stale = sorted(_owned(out_root) - set(files))
    for rel, text in files.items():
        target = out_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    for rel in stale:
        (out_root / rel).unlink()
        print(f"removed {rel}")
    for ns in NAMESPACES:
        ns_root = out_root / ns
        if ns_root.is_dir() and not ns_root.is_symlink():
            dirs = [
                Path(d) for d, _, _ in os.walk(ns_root, topdown=False, followlinks=False)
            ]
            for d in dirs:
                if not d.is_symlink() and not any(d.iterdir()):
                    d.rmdir()
    return files


def check(
    src_dir: Path = SRC_DIR, out_dir: Path = OUT_DIR, accounts_dir: Path = ACCOUNTS_DIR
) -> list[str]:
    """Paths (relative to ``out_dir``) that a build would change, add or remove."""
    files = render_all(src_dir, accounts_dir)
    problems = []
    for rel, text in sorted(files.items()):
        path = out_dir / rel
        if not path.is_file():
            problems.append(f"missing: {rel}")
        elif path.read_bytes() != text.encode("utf-8"):
            problems.append(f"differs: {rel}")
    problems += [f"stale: {rel}" for rel in sorted(_owned(out_dir.resolve()) - set(files))]
    return problems


# --- decrypting (for tests and adapter authors) ------------------------------


def _camel(value):
    """Server cipher with any key spelling to camelCase (``x`` keys untouched)."""
    if isinstance(value, list):
        return [_camel(v) for v in value]
    if isinstance(value, dict):
        return {(k if re.fullmatch(r"x[A-Za-z0-9]+", k) else k[:1].lower() + k[1:]): _camel(v)
                for k, v in value.items()}
    return value


def decrypt(cipher: dict, account: dict) -> dict:
    """Plaintext of a generated cipher (camelCase or PascalCase): the source
    shape, without the generator-only flags. Fails on a wrong key (MAC check)."""
    c = _camel(cipher)
    owner = _owner_key(account, c.get("organizationId"))
    key = owner
    if c.get("key") is not None:
        key = bwcrypto.dec_string(c["key"], owner)

    def dec(s):
        return None if s is None else bwcrypto.dec_string(s, key).decode("utf-8")

    out = {k: c[k] for k in ("id", "type", "folderId", "organizationId") if k in c}
    out["name"] = dec(c["name"])
    if "notes" in c:
        out["notes"] = dec(c["notes"])
    if "login" in c:
        lg = c["login"]
        out["login"] = None if lg is None else {
            "username": dec(lg.get("username")),
            "password": dec(lg.get("password")),
            "uris": [dec(u.get("uri")) for u in lg.get("uris") or []],
            "totp": dec(lg.get("totp")),
            "passwordHistory": [
                {"password": dec(h["password"]), "lastUsedDate": h.get("lastUsedDate")}
                for h in c.get("passwordHistory") or []
            ],
        }
    if "fields" in c:
        out["fields"] = None if c["fields"] is None else [
            {"name": dec(f.get("name")), "value": dec(f.get("value")), "type": f["type"]}
            for f in c["fields"]
        ]
    for k in ("creationDate", "revisionDate", "deletedDate", "edit", "viewPassword"):
        if k in c:
            out[k] = c[k]
    return out


def cmd_build(args: argparse.Namespace) -> int:
    try:
        files = build(args.src, args.out, args.accounts)
    except GenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"built {len(files)} file(s)")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        problems = check(args.src, args.out, args.accounts)
    except GenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for line in problems:
        print(line)
    if problems:
        print("generated files are out of date: run `gen.py build`", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("accounts", help="write vectors/accounts/*.json").set_defaults(func=cmd_accounts)
    for name, func, text in (
        ("build", cmd_build, "write vectors/generated from vectors/src"),
        ("check", cmd_check, "fail when vectors/generated is out of date"),
    ):
        p = sub.add_parser(name, help=text)
        p.add_argument("--src", type=Path, default=SRC_DIR)
        p.add_argument("--out", type=Path, default=OUT_DIR)
        p.add_argument("--accounts", type=Path, default=ACCOUNTS_DIR)
        p.set_defaults(func=func)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
