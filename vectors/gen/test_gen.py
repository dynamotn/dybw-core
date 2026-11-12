"""Tests for the scenario schemas (and, in later commits, the generator)."""

import base64
import json
import re
import sys
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

sys.path.insert(0, str(Path(__file__).resolve().parent))

VECTORS = Path(__file__).resolve().parent.parent
SOURCE_SCHEMA = VECTORS / "schema" / "source.schema.json"
SCENARIO_SCHEMA = VECTORS / "schema" / "scenario.schema.json"
README = VECTORS / "README.md"

MINIMAL = {
    "id": "read/minimal",
    "spec": "1.5",
    "sections": ["§4"],
    "account": "pbkdf2",
    "namespaces": ["bwss"],
    "ciphers": [],
    "expect": {"read": {"items": [], "skipped": [], "uninspectable": []}},
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    """Both schemas by $id, so scenario.schema.json can $ref source.schema.json."""
    reg = Registry()
    for path in (SOURCE_SCHEMA, SCENARIO_SCHEMA):
        doc = load(path)
        reg = reg.with_resource(doc["$id"], Resource.from_contents(doc))
    return reg


def check(instance: dict, path: Path) -> None:
    """Validate against a schema file, resolving cross-file refs."""
    jsonschema.Draft202012Validator(load(path), registry=_registry()).validate(instance)


def test_source_schema_accepts_minimal():
    check(MINIMAL, SOURCE_SCHEMA)


def test_source_schema_rejects_unknown_key():
    with pytest.raises(jsonschema.ValidationError):
        check({**MINIMAL, "foo": 1}, SOURCE_SCHEMA)


def reason_enums(node) -> list[list[str]]:
    """Every enum attached to a property named `reason`, anywhere in a schema."""
    found = []
    if isinstance(node, dict):
        props = node.get("properties")
        if isinstance(props, dict) and "enum" in props.get("reason", {}):
            found.append(props["reason"]["enum"])
        for value in node.values():
            found.extend(reason_enums(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(reason_enums(value))
    return found


def test_reason_codes_listed():
    """The README's Reason codes table and the schema enum list the same codes."""
    # scenario.schema.json shares this enum through a $ref.
    enums = reason_enums(load(SOURCE_SCHEMA))
    assert enums, "schema defines no reason enum"
    readme = README.read_text(encoding="utf-8")
    section = readme.split("## Reason codes", 1)[1]
    listed = set(re.findall(r"^\|\s*`([a-z0-9-]+)`\s*\|", section, re.MULTILINE))
    for codes in enums:
        assert set(codes) == listed, set(codes) ^ listed


ENC = "2.AAAA|BBBB|CCCC"


def generated(cipher: dict) -> dict:
    return {
        "id": "read/x",
        "spec": "1.5",
        "sections": ["§4"],
        "account": "pbkdf2",
        "namespace": "bwss",
        "generator": "1",
        "ciphers": [cipher],
        "expect": {"read": {"items": [], "skipped": [], "uninspectable": []}},
    }


@pytest.mark.parametrize(
    "cipher",
    [
        {"id": "c1", "type": 1, "name": ENC, "notes": None, "key": ENC,
         "fields": [{"name": ENC, "value": ENC, "type": 1}],
         "login": {"username": ENC, "uris": [{"uri": ENC, "match": None}]},
         "revisionDate": "2026-01-01T00:00:00Z"},
        {"Id": "c1", "Type": 1, "Name": ENC, "Notes": None,
         "Fields": [{"Name": ENC, "Value": ENC, "Type": 1}],
         "Login": {"Username": ENC}, "RevisionDate": "2026-01-01T00:00:00Z"},
    ],
)
def test_scenario_schema_accepts_both_key_cases(cipher):
    check(generated(cipher), SCENARIO_SCHEMA)


def test_scenario_schema_rejects_plaintext_name():
    bad = {"id": "c1", "type": 1, "name": "plain"}
    with pytest.raises(jsonschema.ValidationError):
        check(generated(bad), SCENARIO_SCHEMA)


def test_source_schema_accepts_later_shapes():
    src = {**MINIMAL, "namespaces": ["obsidian"],
           "device": {"base": {"a": {"cipher": "c", "revisionDate": "2026-01-01T00:00:00Z", "value": "v"}},
                      "pendingCreates": []},
           "local": {"a": None},
           "operation": {"kind": "set-value", "id": "a", "value": "v",
                         "fresh": {"id": "c", "type": 1, "name": "n"}},
           "expect": {"write": {"requests": [{"method": "trash", "cipher": "c"}]},
                      "plan": [{"kind": "conflict", "id": "a", "conflict": "both-changed"}]}}
    check(src, SOURCE_SCHEMA)
    src["expect"]["plan"][0]["conflict"] = "nope"
    with pytest.raises(jsonschema.ValidationError):
        check(src, SOURCE_SCHEMA)


def test_source_schema_accepts_acknowledged_origins():
    """ADR 0018: the host may follow redirects, and a refused read lists the requests sent (none)."""
    options = {"server": "cloud", "followsRedirects": True, "acknowledged": ["https://vectors.invalid"]}
    check(with_expect({"read": {"error": "origin-not-acknowledged", "sent": []}}, options=options), SOURCE_SCHEMA)
    rejects(with_expect({"read": {"error": "origin-not-acknowledged"}}))
    rejects(with_expect({"read": {"error": "wrong-origin", "sent": []}}))
    rejects(with_expect({"read": {"items": [], "skipped": [], "uninspectable": []}}, options={"server": "eu"}))


def with_expect(expect: dict, **extra) -> dict:
    return {**MINIMAL, **extra, "expect": expect}


def rejects(instance: dict, path: Path = SOURCE_SCHEMA) -> None:
    with pytest.raises(jsonschema.ValidationError):
        check(instance, path)


def test_generated_rejects_typo_key():
    rejects(generated({"id": "c", "type": 1, "name": ENC, "nots": "plain secret"}), SCENARIO_SCHEMA)


def test_generated_rejects_mixed_case_cipher():
    rejects(generated({"id": "c", "type": 1, "name": ENC, "Id": "d", "Type": 2, "Name": ENC}), SCENARIO_SCHEMA)


def test_generated_rejects_mixed_case_nested():
    cipher = {"id": "c", "type": 1, "name": ENC, "login": {"password": ENC, "Password": ENC}}
    rejects(generated(cipher), SCENARIO_SCHEMA)
    cipher = {"id": "c", "type": 1, "name": ENC, "login": {"Password": ENC}}
    rejects(generated(cipher), SCENARIO_SCHEMA)


def test_generated_allows_x_extra_in_both_cases():
    check(generated({"id": "c", "type": 1, "name": ENC, "xFoo": 1}), SCENARIO_SCHEMA)
    check(generated({"Id": "c", "Type": 1, "Name": ENC, "xFoo": 1}), SCENARIO_SCHEMA)


def test_source_extra_must_use_x_names():
    ok = {"id": "c", "type": 1, "name": "n", "extra": {"xFoo": 1}}
    check({**MINIMAL, "ciphers": [ok]}, SOURCE_SCHEMA)
    rejects({**MINIMAL, "ciphers": [{**ok, "extra": {"notes": "x"}}]})


def test_trash_carries_only_method_and_cipher():
    ok = {"method": "trash", "cipher": "c"}
    check(with_expect({"write": {"requests": [ok]}}), SOURCE_SCHEMA)
    rejects(with_expect({"write": {"requests": [{**ok, "name": "n"}]}}))
    rejects(with_expect({"write": {"requests": [{"method": "trash", "cipher": None}]}}))


def _request(method: str, cipher) -> dict:
    return {"method": method, "cipher": cipher, "type": 1, "name": "n", "notes": None, "login": None,
            "fields": [], "organizationId": None, "folderId": None,
            "lastKnownRevisionDate": "<now>", "hasItemKey": False, "extra": {}}


def test_post_needs_null_cipher_put_needs_id():
    check(with_expect({"write": {"requests": [_request("POST", None), _request("PUT", "c")]}}), SOURCE_SCHEMA)
    rejects(with_expect({"write": {"requests": [_request("POST", "c")]}}))
    rejects(with_expect({"write": {"requests": [_request("PUT", None)]}}))


def test_null_field_value_accepted():
    cipher = {"id": "c", "type": 1, "name": "n", "fields": [{"name": "a", "value": None, "type": 0}]}
    check({**MINIMAL, "ciphers": [cipher]}, SOURCE_SCHEMA)
    req = _request("PUT", "c")
    req["fields"] = [{"name": "a", "value": None, "type": 1}]
    check(with_expect({"write": {"requests": [req]}}), SOURCE_SCHEMA)


def test_unexpanded_ns_id_rejected():
    item = {"cipher": "c", "id": "{ns}-x", "value": "v", "source": "field"}
    rejects(with_expect({"read": {"items": [item], "skipped": [], "uninspectable": []}}))
    check(with_expect({"read": {"items": [{**item, "id": "bwss-x"}], "skipped": [], "uninspectable": []}}),
          SOURCE_SCHEMA)


# --- crypto and accounts ----------------------------------------------------

ACCOUNTS = VECTORS / "accounts"
KAT = VECTORS / "crypto" / "vectors.json"


def _account_files() -> list[Path]:
    return sorted(ACCOUNTS.glob("*.json"))


def test_master_key_matches_kat():
    import bwcrypto

    kat = load(KAT)
    pbkdf2 = {"type": "pbkdf2", "iterations": kat["pbkdf2"]["iterations"]}
    argon = {
        "type": "argon2id",
        "iterations": kat["argon2id"]["iterations"],
        "memory": kat["argon2id"]["memory"],
        "parallelism": kat["argon2id"]["parallelism"],
    }
    mk = bwcrypto.master_key(kat["password"], kat["email"], pbkdf2)
    assert base64.b64encode(mk).decode() == kat["pbkdf2"]["masterKey"]
    assert base64.b64encode(bwcrypto.stretch(mk)).decode() == kat["pbkdf2"]["stretched"]
    mk = bwcrypto.master_key(kat["password"], kat["email"], argon)
    assert base64.b64encode(mk).decode() == kat["argon2id"]["masterKey"]


def test_enc_string_matches_kat():
    import bwcrypto

    kat = load(KAT)
    key = base64.b64decode(kat["userKey"])
    iv = bytes(range(100, 116))
    for case in kat["encStrings"]:
        assert bwcrypto.enc_string(case["plain"].encode(), key, iv) == case["enc"]


def test_enc_string_round_trip():
    import bwcrypto

    k = bytes(range(64))
    iv = bytes(range(16))
    s = bwcrypto.enc_string(b"x", k, iv)
    assert bwcrypto.dec_string(s, k) == b"x"
    head, rest = s.split(".", 1)
    iv_b, ct_b, mac_b = rest.split("|")
    mac = bytearray(base64.b64decode(mac_b))
    mac[0] ^= 1
    bad = f"{head}.{iv_b}|{ct_b}|{base64.b64encode(bytes(mac)).decode()}"
    with pytest.raises(ValueError):
        bwcrypto.dec_string(bad, k)


def test_iv_for_is_deterministic_and_path_sensitive():
    import bwcrypto

    seed = b"s" * 32
    assert bwcrypto.iv_for(seed, "a", "b") == bwcrypto.iv_for(seed, "a", "b")
    assert len(bwcrypto.iv_for(seed, "a")) == 16
    assert bwcrypto.iv_for(seed, "a", "b") != bwcrypto.iv_for(seed, "a", "c")


def test_accounts_exist():
    assert {p.stem for p in _account_files()} == {"pbkdf2", "argon2id", "org", "cose", "cose-v2"}


def test_accounts_unlock():
    import bwcrypto

    for path in _account_files():
        acc = load(path)
        mk = bwcrypto.master_key(acc["password"], acc["email"], acc["kdf"])
        user_key = bwcrypto.dec_string(acc["profileKey"], bwcrypto.stretch(mk))
        assert user_key == base64.b64decode(acc["userKey"])
        if not acc["name"].startswith("cose"):
            assert len(user_key) == 64


def test_rsa_oaep_wrap_decrypts_with_cryptography():
    import bwcrypto
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    acc = load(ACCOUNTS / "org.json")
    priv = serialization.load_der_private_key(base64.b64decode(acc["privateKey"]), None)
    pub = serialization.load_der_public_key(base64.b64decode(acc["publicKey"]))
    assert priv.public_key().public_numbers() == pub.public_numbers()
    assert priv.key_size == 2048
    assert [o["id"] for o in acc["organizations"]] == ["org-a", "org-b"]
    for org in acc["organizations"]:
        key = base64.b64decode(org["key"])
        assert len(key) == 64
        typ, body = org["wrapped"].split(".", 1)
        assert typ == "4"
        oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
        assert priv.decrypt(base64.b64decode(body), oaep) == key
    # type 3 (SHA-256) too
    pub_der = base64.b64decode(acc["publicKey"])
    wrapped = bwcrypto.rsa_oaep_wrap(b"k" * 64, pub_der, sha1=False, seed=b"\x07" * 32)
    typ, body = wrapped.split(".", 1)
    assert typ == "3"
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    assert priv.decrypt(base64.b64decode(body), oaep) == b"k" * 64


def test_drbg_rsa_is_deterministic():
    import bwcrypto

    a = bwcrypto.rsa_key_from_seed(b"\x01" * 32, bits=512)
    b = bwcrypto.rsa_key_from_seed(b"\x01" * 32, bits=512)
    c = bwcrypto.rsa_key_from_seed(b"\x02" * 32, bits=512)
    assert a.private_numbers() == b.private_numbers() != c.private_numbers()


# --- generator: build / check -------------------------------------------------

import bwcrypto
import gen

FIXTURE = {
    "id": "read/fixture",
    "spec": "1.5",
    "sections": ["§4"],
    "account": "org",
    "namespaces": ["bwss", "obsidian"],
    "options": {"organizations": True},
    "ciphers": [
        {
            "id": "c1",
            "type": 1,
            "name": "Login {ns}",
            "notes": "",
            "login": {
                "username": "user",
                "password": "pw-ünï-😀",
                "uris": ["https://example.invalid"],
                "totp": None,
                "passwordHistory": [{"password": "old", "lastUsedDate": "2025-01-01T00:00:00Z"}],
            },
            "fields": [
                {"name": "{ns}:id", "value": "token", "type": 0},
                {"name": "{ns}:empty", "value": None, "type": 0},
            ],
            "itemKey": True,
        },
        {"id": "c2", "type": 2, "name": "Note", "notes": None, "fields": None},
        {
            "id": "c3",
            "type": 1,
            "name": "Org login",
            "organizationId": "org-a",
            "notes": "n",
            "login": None,
            "pascalCase": True,
            "extra": {"xFlag": 1},
        },
    ],
    "expect": {"read": {"items": [], "skipped": [], "uninspectable": []}},
}


@pytest.fixture
def tree(tmp_path):
    src = tmp_path / "src"
    (src / "read").mkdir(parents=True)
    (src / "read" / "fixture.json").write_text(json.dumps(FIXTURE), encoding="utf-8")
    return src, tmp_path / "out"


def run(cmd, src, out):
    return gen.main([cmd, "--src", str(src), "--out", str(out)])


def account_org():
    return gen.load_account("org")


def built(out, ns="bwss"):
    return load(out / ns / "read" / "fixture.json")


def test_zero_sources_build_nothing(tmp_path):
    (tmp_path / "src").mkdir()
    assert run("build", tmp_path / "src", tmp_path / "out") == 0
    assert list((tmp_path / "out").rglob("*.json")) == []
    assert run("check", tmp_path / "src", tmp_path / "out") == 0


def test_build_is_deterministic(tree, tmp_path):
    src, _ = tree
    a, b = tmp_path / "a", tmp_path / "b"
    assert run("build", src, a) == 0
    assert run("build", src, b) == 0
    names = sorted(p.relative_to(a).as_posix() for p in a.rglob("*.json"))
    assert names == ["bwss/read/fixture.json", "obsidian/read/fixture.json"]
    for n in names:
        assert (a / n).read_bytes() == (b / n).read_bytes()
        assert (a / n).read_bytes().endswith(b"}\n")


def test_check_detects_stale(tree):
    src, out = tree
    assert run("build", src, out) == 0
    assert run("check", src, out) == 0
    target = out / "bwss" / "read" / "fixture.json"
    target.write_text(target.read_text(encoding="utf-8").replace("generator", "generatoR"))
    assert run("check", src, out) == 1


def test_check_detects_extra_file(tree, capsys):
    src, out = tree
    assert run("build", src, out) == 0
    (out / "bwss" / "read" / "old.json").write_text('{"generator": "dybw-vectors-gen 0"}\n')
    assert run("check", src, out) == 1
    assert "stale: bwss/read/old.json" in capsys.readouterr().out
    # build removes it again
    assert run("build", src, out) == 0
    assert not (out / "bwss" / "read" / "old.json").exists()
    assert run("check", src, out) == 0


def test_ns_expanded(tree):
    src, out = tree
    assert run("build", src, out) == 0
    acc = account_org()
    for ns in ("bwss", "obsidian"):
        doc = built(out, ns)
        assert doc["namespace"] == ns and "namespaces" not in doc
        plain = gen.decrypt(doc["ciphers"][0], acc)
        assert [f["name"] for f in plain["fields"]] == [f"{ns}:id", f"{ns}:empty"]
        assert plain["name"] == f"Login {ns}"


def test_item_key_used(tree):
    import bwcrypto

    src, out = tree
    run("build", src, out)
    acc = account_org()
    c = built(out)["ciphers"][0]
    user_key = base64.b64decode(acc["userKey"])
    assert "key" in c
    with pytest.raises(ValueError):
        bwcrypto.dec_string(c["name"], user_key)
    item_key = bwcrypto.dec_string(c["key"], user_key)
    assert len(item_key) == 64
    assert bwcrypto.dec_string(c["name"], item_key) == b"Login bwss"
    assert "key" not in built(out)["ciphers"][1]


def test_org_cipher_uses_org_key(tree):
    import bwcrypto

    src, out = tree
    run("build", src, out)
    c = built(out)["ciphers"][2]
    org_key = base64.b64decode(acc_org_key("org-a"))
    assert bwcrypto.dec_string(c["Name"], org_key) == b"Org login"


def acc_org_key(org_id):
    return next(o["key"] for o in account_org()["organizations"] if o["id"] == org_id)


def test_pascal_case_emitted(tree):
    src, out = tree
    run("build", src, out)
    c = built(out)["ciphers"][2]
    assert {"Id", "Type", "Name", "Notes", "Login", "OrganizationId", "xFlag"} <= set(c)
    assert "name" not in c and "itemKey" not in c and "pascalCase" not in c and "extra" not in c
    plain = gen.decrypt(c, account_org())
    assert plain["name"] == "Org login" and plain["notes"] == "n" and plain["login"] is None


def test_null_vs_empty_preserved(tree):
    src, out = tree
    run("build", src, out)
    acc = account_org()
    c1, c2, _ = built(out)["ciphers"]
    assert c2["notes"] is None and c2["fields"] is None
    assert c1["notes"] is not None and c1["notes"].startswith("2.")
    p1 = gen.decrypt(c1, acc)
    assert p1["notes"] == ""
    assert p1["login"]["totp"] is None
    assert p1["login"]["password"] == "pw-ünï-😀"
    assert p1["fields"][1]["value"] is None
    assert p1["login"]["passwordHistory"][0]["password"] == "old"
    assert built(out)["ciphers"][1]["secureNote"] == {"type": 0}


def test_invalid_source_names_file(tree, capsys):
    src, out = tree
    bad = {**FIXTURE, "bogus": 1}
    (src / "read" / "fixture.json").write_text(json.dumps(bad), encoding="utf-8")
    assert run("build", src, out) == 1
    assert "fixture.json" in capsys.readouterr().err


def test_build_refuses_foreign_json(tree):
    src, _ = tree
    out = src.parent / "wrongout"
    out.mkdir()
    (out / "x.json").write_text('{"keep": true}\n')
    assert run("build", src, out) == 1
    assert (out / "x.json").read_text() == '{"keep": true}\n'
    assert not (out / "bwss").exists()


def test_orphan_removal_only_ours(tree):
    src, out = tree
    run("build", src, out)
    (out / "bwss" / "foreign.json").write_text('{"a": 1}\n')
    assert run("check", src, out) == 0
    run("build", src, out)
    assert (out / "bwss" / "foreign.json").exists()


def test_symlinked_dir_not_followed(tree, tmp_path):
    src, out = tree
    run("build", src, out)
    other = tmp_path / "elsewhere"
    other.mkdir()
    victim = other / "v.json"
    victim.write_text(json.dumps({"generator": "dybw-vectors-gen 1"}))
    (out / "bwss" / "link").symlink_to(other, target_is_directory=True)
    run("build", src, out)
    assert victim.exists()


def test_duplicate_cipher_ids_rejected(tree, capsys):
    src, out = tree
    dup = {**FIXTURE, "ciphers": [FIXTURE["ciphers"][1], FIXTURE["ciphers"][1]]}
    (src / "read" / "fixture.json").write_text(json.dumps(dup), encoding="utf-8")
    assert run("build", src, out) == 1
    assert "duplicate cipher ids" in capsys.readouterr().err


def test_fresh_keeps_item_key_and_round_trips(tree):
    import bwcrypto

    src, out = tree
    fresh = {**FIXTURE["ciphers"][0], "name": "Fresh {ns}"}
    doc = {**FIXTURE, "operation": {"kind": "set-value", "id": "c1", "value": "v", "fresh": fresh}}
    (src / "read" / "fixture.json").write_text(json.dumps(doc), encoding="utf-8")
    assert run("build", src, out) == 0
    acc = account_org()
    built_doc = built(out)
    orig, fr = built_doc["ciphers"][0], built_doc["operation"]["fresh"]
    user_key = base64.b64decode(acc["userKey"])
    assert bwcrypto.dec_string(fr["key"], user_key) == bwcrypto.dec_string(orig["key"], user_key)
    assert fr["name"] != orig["name"]
    assert gen.decrypt(fr, acc)["name"] == "Fresh bwss"
    assert gen.decrypt(fr, acc)["login"]["password"] == "pw-ünï-😀"


def test_pascal_full_cipher_round_trips(tree):
    src, out = tree
    full = {**FIXTURE["ciphers"][0], "pascalCase": True}
    full["id"] = "p1"
    doc = {**FIXTURE, "ciphers": [full]}
    (src / "read" / "fixture.json").write_text(json.dumps(doc), encoding="utf-8")
    assert run("build", src, out) == 0
    c = built(out)["ciphers"][0]
    assert {"Login", "Fields", "PasswordHistory", "Key"} <= set(c)
    assert set(c["Login"]) == {"Username", "Password", "Totp", "Uris"}
    want = gen.decrypt({k: v for k, v in c.items()}, account_org())
    assert want["login"]["uris"] == ["https://example.invalid"]
    assert want["login"]["passwordHistory"][0]["password"] == "old"
    assert [f["value"] for f in want["fields"]] == ["token", None]


def test_item_key_org_cipher_under_org_key(tree):
    import bwcrypto

    src, out = tree
    c = {**FIXTURE["ciphers"][2], "id": "o1", "itemKey": True, "pascalCase": False}
    doc = {**FIXTURE, "ciphers": [c]}
    (src / "read" / "fixture.json").write_text(json.dumps(doc), encoding="utf-8")
    assert run("build", src, out) == 0
    got = built(out)["ciphers"][0]
    org_key = base64.b64decode(acc_org_key("org-a"))
    item_key = bwcrypto.dec_string(got["key"], org_key)
    assert len(item_key) == 64
    assert bwcrypto.dec_string(got["name"], item_key) == b"Org login"
    with pytest.raises(ValueError):
        bwcrypto.dec_string(got["key"], base64.b64decode(account_org()["userKey"]))


def tampered_tree(tmp_path, tamper, item_key=False):
    src = tmp_path / "src"
    (src / "read").mkdir(parents=True)
    doc = {
        **MINIMAL,
        "id": "read/tamper",
        "ciphers": [
            {
                "id": "c1",
                "type": 2,
                "name": "Note",
                "notes": "body",
                "itemKey": item_key,
                "fields": [
                    {"name": "{ns}:id", "value": "a", "type": 0},
                    {"name": "other", "value": "v", "type": 0},
                ],
                "tamper": tamper,
            }
        ],
    }
    (src / "read" / "tamper.json").write_text(json.dumps(doc), encoding="utf-8")
    return src, tmp_path / "out"


def test_tamper_breaks_only_the_listed_mac(tmp_path):
    import bwcrypto

    src, out = tampered_tree(tmp_path, ["fields[1].name"])
    assert run("build", src, out) == 0
    c = load(out / "bwss" / "read" / "tamper.json")["ciphers"][0]
    assert "tamper" not in c
    key = base64.b64decode(gen.load_account("pbkdf2")["userKey"])
    with pytest.raises(ValueError):
        bwcrypto.dec_string(c["fields"][1]["name"], key)
    assert bwcrypto.dec_string(c["fields"][0]["name"], key) == b"bwss:id"
    assert bwcrypto.dec_string(c["fields"][1]["value"], key) == b"v"
    assert bwcrypto.dec_string(c["notes"], key) == b"body"
    # same IV and ciphertext as the untampered string: only the MAC differs
    clean_src, clean_out = tampered_tree(tmp_path / "clean", [])
    assert run("build", clean_src, clean_out) == 0
    clean = load(clean_out / "bwss" / "read" / "tamper.json")["ciphers"][0]
    t_head, t_mac = c["fields"][1]["name"].rsplit("|", 1)
    c_head, c_mac = clean["fields"][1]["name"].rsplit("|", 1)
    assert t_head == c_head and t_mac != c_mac


def test_tamper_item_key(tmp_path):
    import bwcrypto

    src, out = tampered_tree(tmp_path, ["key"], item_key=True)
    assert run("build", src, out) == 0
    c = load(out / "bwss" / "read" / "tamper.json")["ciphers"][0]
    key = base64.b64decode(gen.load_account("pbkdf2")["userKey"])
    with pytest.raises(ValueError):
        bwcrypto.dec_string(c["key"], key)


def test_tamper_path_must_be_encrypted(tmp_path, capsys):
    src, out = tampered_tree(tmp_path, ["login.password"])
    assert run("build", src, out) == 1
    assert "tamper paths not encrypted: login.password" in capsys.readouterr().err


def test_tamper_rejects_unknown_path(tmp_path):
    src, out = tampered_tree(tmp_path, ["revisionDate"])
    assert run("build", src, out) == 1


def test_read_item_attributes_optional_strings():
    item = {"cipher": "c1", "id": "a", "value": "v", "source": "field"}
    with_attrs = {**MINIMAL, "expect": {"read": {"items": [{**item, "attributes": {"host": " a "}}],
                                                 "skipped": [], "uninspectable": []}}}
    check(with_attrs, SOURCE_SCHEMA)
    bad = json.loads(json.dumps(with_attrs))
    bad["expect"]["read"]["items"][0]["attributes"]["host"] = 1
    with pytest.raises(jsonschema.ValidationError):
        check(bad, SOURCE_SCHEMA)


def test_unicode_values_round_trip_byte_exact():
    import unicodedata

    src_path = VECTORS / "src" / "read" / "unicode-values.json"
    raw = src_path.read_text(encoding="utf-8")
    # written with escapes, so no editor can normalize the decomposed text
    assert raw.isascii() and "\\u0302\\u0301" in raw
    src = json.loads(raw)
    acc = gen.load_account(src["account"])
    nfd = next(i["value"] for i in src["expect"]["read"]["items"] if i["id"] == "nfd")
    assert not unicodedata.is_normalized("NFC", nfd)
    assert unicodedata.normalize("NFD", nfd) == nfd
    long = next(i["value"] for i in src["expect"]["read"]["items"] if i["id"] == "long")
    assert len(long) == 1000
    for ns in src["namespaces"]:
        doc = load(VECTORS / "generated" / ns / "read" / "unicode-values.json")
        assert doc["expect"] == gen.expand_ns(src["expect"], ns)
        for want, got in zip(gen.expand_ns(src["ciphers"], ns), doc["ciphers"], strict=True):
            plain = gen.decrypt(got, acc)
            # exact: None stays None, "" stays "", text compares as UTF-8 bytes
            assert utf8(plain["name"]) == utf8(want["name"])
            assert utf8(plain["notes"]) == utf8(want["notes"])
            assert [(utf8(f["name"]), utf8(f["value"])) for f in plain["fields"]] == [
                (utf8(f["name"]), utf8(f["value"])) for f in want["fields"]
            ]
            assert (plain["login"] is None) == (want["login"] is None)
            if want["login"] is not None:
                assert utf8(plain["login"]["password"]) == utf8(want["login"]["password"])


def utf8(s):
    return None if s is None else s.encode("utf-8")


def test_attr_unicode_names_byte_exact():
    import unicodedata

    raw = (VECTORS / "src" / "read" / "attr" / "exact-match-untrimmed.json").read_text(encoding="utf-8")
    assert raw.isascii() and "\\u0323\\u0302" in raw
    src = json.loads(raw)
    acc = gen.load_account(src["account"])
    attrs = next(i["attributes"] for i in src["expect"]["read"]["items"] if i["id"] == "gamma")
    ((name, value),) = attrs.items()
    assert not unicodedata.is_normalized("NFC", name) and not unicodedata.is_normalized("NFC", value)
    doc = load(VECTORS / "generated" / "bwss" / "read" / "attr" / "exact-match-untrimmed.json")
    c3 = gen.decrypt(next(c for c in doc["ciphers"] if c["id"] == "c3"), acc)
    assert utf8(c3["fields"][1]["name"]) == utf8("bwss:attr:" + name)
    assert utf8(c3["fields"][1]["value"]) == utf8(value)


@pytest.mark.parametrize("value", ["plain text", "base64://4=", "base64:gA=="])
def test_operation_value_accepted(value):
    gen.check_operation_value(value)


@pytest.mark.parametrize(
    "value, why",
    [
        ("base64:aGk=", "valid UTF-8"),
        ("base64://4", "not base64"),
        ("base64:/w=", "not base64"),
        ("base64:_w==", "not base64"),
    ],
)
def test_operation_value_rejected(value, why):
    with pytest.raises(gen.GenError, match=why):
        gen.check_operation_value(value)


def test_build_rejects_utf8_base64_operation(tmp_path, capsys):
    src = tmp_path / "src"
    (src / "write").mkdir(parents=True)
    doc = {
        "id": "write/bad-binary",
        "spec": "1.5",
        "sections": ["§6.1"],
        "account": "pbkdf2",
        "namespaces": ["bwss"],
        "ciphers": [],
        "operation": {"kind": "set-value", "id": "a", "value": "base64:aGk="},
        "expect": {"write": {"requests": []}},
    }
    (src / "write" / "bad-binary.json").write_text(json.dumps(doc), encoding="utf-8")
    assert run("build", src, tmp_path / "out") == 1
    assert "decodes to valid UTF-8" in capsys.readouterr().err


# --- COSE (EncString type 7) --------------------------------------------------

COSE_KAT = VECTORS / "crypto" / "cose-vectors.json"


def test_cose_decrypts_sdk_vectors():
    import bwcrypto

    kat = load(COSE_KAT)
    algs = set()
    for acc in kat["accounts"]:
        key = base64.b64decode(acc["userKey"])
        algs.add(acc["name"])
        for t in acc["texts"]:
            assert bwcrypto.cose_decrypt(t["enc"], key) == t["plain"].encode()
            # the same nonce gives the same message, byte for byte
            nonce = bwcrypto.cbor_decode(base64.b64decode(t["enc"][2:]))[1][5]
            assert bwcrypto.cose_encrypt(t["plain"].encode(), key, nonce, "utf8") == t["enc"]
    assert algs == {"xaes-256-gcm", "xchacha20-poly1305"}


def test_xchacha_rejects_wrong_aad():
    import bwcrypto

    key, nonce = bytes(range(32)), bytes(range(24))
    ct = bwcrypto.xchacha20poly1305(key, nonce, b"hi", b"aad")
    assert bwcrypto.xchacha20poly1305_open(key, nonce, ct, b"aad") == b"hi"
    with pytest.raises(ValueError):
        bwcrypto.xchacha20poly1305_open(key, nonce, ct, b"other")


def test_cose_decrypt_rejects_bad_padding():
    import bwcrypto

    acc = load(COSE_KAT)["accounts"][0]
    key = base64.b64decode(acc["userKey"])
    k = bwcrypto._cose_parts(key)
    protected = bwcrypto._protected(k, "utf8")
    nonce = bytes(range(24))
    for body in (b"abc\x00", b"abc\x05", b""):
        ct = bwcrypto._seal(k[3], k[-1], nonce, body, bwcrypto._enc_structure(protected), open_=False)
        s = "7." + base64.b64encode(bwcrypto.cbor_encode([protected, {5: nonce}, ct])).decode()
        with pytest.raises(ValueError, match="bad padding"):
            bwcrypto.cose_decrypt(s, key)


def test_cose_account_unlocks():
    import bwcrypto

    acc = load(ACCOUNTS / "cose.json")
    mk = bwcrypto.master_key(acc["password"], acc["email"], acc["kdf"])
    user_key = bwcrypto.dec_string(acc["profileKey"], bwcrypto.stretch(mk))
    assert user_key == base64.b64decode(acc["userKey"])
    assert user_key[-1] == 1  # the padded COSE_Key of Bitwarden's storage format
    assert bwcrypto.cose_alg(user_key) == -70010  # XAES-256-GCM, the V2 user key
    assert bwcrypto.cose_key(base64.b64decode(acc["seed"])) == user_key


def test_cose_cipher_is_type7():
    doc = {**FIXTURE, "account": "cose", "options": {}}
    doc["ciphers"] = [dict(FIXTURE["ciphers"][0], itemKey=False), FIXTURE["ciphers"][1]]
    account = gen.load_account("cose")
    scenario = gen.render_scenario(doc, "bwss", account)
    strings = []

    def walk(v):
        if isinstance(v, str) and v.startswith(("2.", "7.")):
            strings.append(v)
        elif isinstance(v, dict):
            [walk(x) for x in v.values()]
        elif isinstance(v, list):
            [walk(x) for x in v]

    walk(scenario["ciphers"])
    assert strings and all(s.startswith("7.") for s in strings)
    plain = gen.decrypt(scenario["ciphers"][0], account)
    assert plain["name"] == "Login bwss" and plain["login"]["password"] == "pw-ünï-😀"
    with pytest.raises(gen.GenError, match="item key"):
        gen.render_scenario({**doc, "ciphers": [FIXTURE["ciphers"][0]]}, "bwss", account)


BASE16 = {"cipher": "c", "revisionDate": "2026-01-01T00:00:00Z", "value": "v"}


def with_device(entry: dict, **extra) -> dict:
    return {**MINIMAL, "spec": "1.6", "device": {"base": {"a": {**BASE16, **entry}}, "pendingCreates": []}, **extra}


def test_spec_16_accepted():
    check({**MINIMAL, "spec": "1.6"}, SOURCE_SCHEMA)
    check({**MINIMAL, "spec": "1.5"}, SOURCE_SCHEMA)
    check({**generated({"id": "c1", "type": 1, "name": ENC}), "spec": "1.6"}, SCENARIO_SCHEMA)
    rejects({**MINIMAL, "spec": "1.4"})


def test_written_is_capped_at_six():
    check(with_device({"written": ["1", "2", "3", "4", "5", "6"], "writeBackConfirmed": True}), SOURCE_SCHEMA)
    rejects(with_device({"written": ["1", "2", "3", "4", "5", "6", "7"]}))
    rejects(with_device({"written": [1]}))
    rejects(with_device({"writeBackConfirmed": "yes"}))


@pytest.mark.parametrize("answer", ["write-to-login", "keep-separate", "unanswered"])
def test_answer_values(answer):
    ops = [{"kind": "set-value", "id": "a", "value": "v"},
           {"kind": "create", "id": "a", "value": "v", "folderId": None},
           {"kind": "delete", "id": "a"}]
    for op in ops:
        check({**MINIMAL, "operation": {**op, "answer": answer}}, SOURCE_SCHEMA)
        rejects({**MINIMAL, "operation": {**op, "answer": "later"}})


def test_1_6_expectations():
    q = {"write": {"question": "first-write-back"}}
    check(with_expect(q), SOURCE_SCHEMA)
    check(with_expect({"write": {"question": "evicts-foreign-history"}}), SOURCE_SCHEMA)
    rejects(with_expect({"write": {"question": "why"}}))
    check({**MINIMAL, "options": {"acceptRollback": True}}, SOURCE_SCHEMA)
    check(with_expect({"plan": [{"kind": "rollback", "id": "a"}]}), SOURCE_SCHEMA)
    read = {"items": [], "skipped": [{"cipher": "c", "reason": "invalid-base64"}], "uninspectable": [],
            "duplicates": [{"id": "a", "kept": "c", "left": [], "boundKept": True}]}
    check(with_expect({"read": read}), SOURCE_SCHEMA)


# --- blob ciphers and the cose-v2 account (data model 1.6) ----------------------

SDK_M3 = VECTORS / "crypto" / "sdk-m3.json"


def _sdk_blob(name: str):
    """(cek, envelope, plaintext) of one recorded DataEnvelope of the SDK."""
    entry = load(SDK_M3)["v1"][name]
    key = next(v["value"] for k, v in entry.items() if k.endswith("_CEK"))
    env = next(v["value"] for k, v in entry.items() if k.endswith("_ENVELOPE"))
    return base64.b64decode(key), base64.b64decode(env), entry["plaintext"]


def test_envelope_opens_sdk_vector():
    """The sealed.rs vector's envelope uses XChaCha20-Poly1305 and a 24-byte nonce; ours use AES-256-GCM."""
    import bwcrypto

    sealed = load(SDK_M3)["sealed"]
    blob = json.loads(sealed["TEST_VECTOR_SEALED_BLOB"]["value"])
    wrapping = base64.b64decode(sealed["TEST_VECTOR_WRAPPING_KEY"]["value"])
    cek = bwcrypto.dec_string(blob["wrapped_cek"], wrapping)
    assert bwcrypto.cose_alg(cek) == bwcrypto.ALG_XCHACHA
    env = base64.b64decode(blob["envelope"])
    assert bwcrypto.cbor_decode(bwcrypto.open_envelope(env, cek)) == sealed["plaintext"]
    for name in load(SDK_M3)["v1"]:
        key, env, plain = _sdk_blob(name)
        assert bwcrypto.cbor_decode(bwcrypto.open_envelope(env, key)) == {"version": "1", "content": plain["content"]}
    with pytest.raises(ValueError):
        bwcrypto.open_envelope(env[:-1] + bytes([env[-1] ^ 1]), key)


def test_envelope_round_trips_every_algorithm_and_rejects_a_wrong_key():
    import bwcrypto

    for alg, nonce_len in ((bwcrypto.ALG_AES_GCM, 12), (bwcrypto.ALG_XCHACHA, 24), (bwcrypto.ALG_XAES, 24)):
        cek = bwcrypto.cek_key(b"k" * 16, b"s" * 32, alg)
        env = bwcrypto.data_envelope(b"\xa0", cek, b"n" * nonce_len)
        assert bwcrypto.open_envelope(env, cek) == b"\xa0"
        other = bwcrypto.cek_key(b"j" * 16, b"s" * 32, alg)
        with pytest.raises(ValueError, match="another key"):
            bwcrypto.open_envelope(env, other)
    with pytest.raises(ValueError, match="unsupported"):
        bwcrypto.data_envelope(b"\xa0", bwcrypto.cek_key(b"k" * 16, b"s" * 32, 99), b"n" * 12)
    plain_cose = bwcrypto.cose_encrypt(b"x", bwcrypto.cose_key(b"s" * 32), b"n" * 24, "utf8")
    with pytest.raises(ValueError, match="not a DataEnvelope"):
        bwcrypto.open_envelope(base64.b64decode(plain_cose[2:]), bwcrypto.cose_key(b"s" * 32))


BLOB_FIXTURE = {
    "id": "read/blob",
    "spec": "1.6",
    "sections": ["§4"],
    "account": "cose-v2",
    "namespaces": ["bwss"],
    "ciphers": [
        {
            "id": "b1",
            "type": 1,
            "format": "blob",
            "name": "Blob {ns}",
            "notes": "n",
            "login": {
                "username": "u",
                "password": "pw-ünï",
                "uris": ["https://a.invalid", "https://b.invalid"],
                "totp": None,
                "passwordHistory": [{"password": "old", "lastUsedDate": "2025-01-01T00:00:00Z"}],
            },
            "fields": [{"name": "{ns}:id", "value": "x", "type": 0}, {"name": "f", "value": None, "type": 1}],
        },
        {"id": "b2", "type": 2, "format": "blob", "name": "Note", "notes": None, "fields": []},
    ],
    "expect": {"read": {"items": [], "skipped": [], "uninspectable": []}},
}


def _blob(**over):
    account = gen.load_account("cose-v2")
    src = {**BLOB_FIXTURE["ciphers"][0], **over}
    return gen.encrypt_cipher(gen.expand_ns(src, "bwss"), account, "read/blob", "bwss"), account


def test_blob_round_trip():
    scenario = gen.render_scenario(BLOB_FIXTURE, "bwss", gen.load_account("cose-v2"))
    account = gen.load_account("cose-v2")
    login, note = scenario["ciphers"]
    assert (login["name"], login["notes"], login["login"], login["fields"], login["passwordHistory"]) == (None,) * 5
    assert login["key"].startswith("7.")  # an item key under a COSE user key is type 7
    assert json.loads(login["data"])["wrapped_cek"].startswith("2.")
    assert list(json.loads(login["data"])) == ["format_version", "wrapped_cek", "envelope"]
    assert gen.open_blob(login, account) == {
        "version": "1",
        "content": {
            "name": "Blob bwss",
            "notes": "n",
            "typeData": {
                "type": "login",
                "username": "u",
                "password": "pw-ünï",
                "passwordRevisionDate": None,
                "uris": [{"uri": "https://a.invalid", "match": None}, {"uri": "https://b.invalid", "match": None}],
                "totp": None,
                "autofillOnPageLoad": None,
            },
            "fields": [
                {"name": "bwss:id", "value": "x", "type": 0, "linkedId": None},
                {"name": "f", "value": None, "type": 1, "linkedId": None},
            ],
            "passwordHistory": [{"password": "old", "lastUsedDate": "2025-01-01T00:00:00Z"}],
        },
    }
    assert gen.open_blob(note, account)["content"] == {
        "name": "Note",
        "notes": None,
        "typeData": {"type": "secureNote", "secureNoteType": 0},
    }


def test_blob_on_a_legacy_account_wraps_the_item_key_as_type_2():
    account = gen.load_account("pbkdf2")
    src = gen.expand_ns(BLOB_FIXTURE["ciphers"][1], "bwss")
    cipher = gen.encrypt_cipher(src, account, "read/blob", "bwss")
    assert cipher["key"].startswith("2.")
    assert gen.open_blob(cipher, account)["content"]["name"] == "Note"


def test_blob_pascal_case_and_versions():
    cipher, account = _blob(pascalCase=True, formatVersion=2, contentVersion="2", extra={"xK": 1})
    assert "Data" in cipher and "data" not in cipher and cipher["xK"] == 1
    assert json.loads(cipher["Data"])["format_version"] == 2
    assert gen.open_blob(cipher, account)["version"] == "2"


def test_blob_padding_matches_sdk():
    """The SDK's pad_bytes(content, 64): a minimum length of 64, and at least one byte."""
    import bwcrypto

    cek = bwcrypto.cek_key(b"k" * 16, b"s" * 32)
    for n, want in ((0, 64), (1, 64), (63, 64), (64, 65), (65, 66), (200, 201)):
        content = b"\x07" * n
        env = bwcrypto.data_envelope(content, cek, b"n" * 12)
        _, _, ct = bwcrypto.cbor_decode(env)
        assert len(ct) - 16 == want
        assert bwcrypto.open_envelope(env, cek) == content
    assert bwcrypto.pad(b"\x07" * 64, 64)[-1] == 1
    # every recorded SDK envelope unpads under this rule: the last byte n, and n bytes of value n
    for name in load(SDK_M3)["v1"]:
        key, env, _ = _sdk_blob(name)
        k = bwcrypto._cose_parts(key)
        protected, unprotected, ct = bwcrypto.cbor_decode(env)
        plain = bwcrypto._seal(k[3], k[-1], unprotected[5], ct, bwcrypto._enc_structure(protected), open_=True)
        n = plain[-1]
        assert 0 < n <= len(plain) and plain[-n:] == bytes([n]) * n
        assert bwcrypto.pad(plain[:-n], 64) == plain


def test_blob_extra_is_sealed_after_the_known_keys():
    cipher, account = _blob(blobExtra={"xUnknown": {"kept": [1, True, None]}})
    content = gen.open_blob(cipher, account)["content"]
    assert content["xUnknown"] == {"kept": [1, True, None]}
    assert list(content)[-1] == "xUnknown"
    assert "xUnknown" not in cipher
    src = {k: v for k, v in BLOB_FIXTURE["ciphers"][0].items() if k != "format"}
    with pytest.raises(gen.GenError, match="blobExtra needs format blob"):
        gen.encrypt_cipher(gen.expand_ns({**src, "blobExtra": {"xK": 1}}, "bwss"), account, "read/blob", "bwss")


def test_blob_tamper_breaks_only_the_named_part():
    for part in ("envelope", "wrapped_cek"):
        cipher, account = _blob(tamper=[part])
        with pytest.raises(ValueError):
            gen.open_blob(cipher, account)
    cipher, account = _blob()
    assert gen.open_blob(cipher, account)["content"]["name"] == "Blob bwss"


def test_blob_is_rejected_where_it_cannot_be_written():
    account = gen.load_account("cose-v2")
    for over, why in (
        ({"type": 9}, "known type"),
        ({"tamper": ["name"]}, "not encrypted"),
    ):
        src = gen.expand_ns({**BLOB_FIXTURE["ciphers"][0], **over}, "bwss")
        with pytest.raises(gen.GenError, match=why):
            gen.encrypt_cipher(src, account, "read/blob", "bwss")


def test_organization_blob_is_sealed_under_the_organization_key():
    account = gen.load_account("org")
    src = gen.expand_ns({**BLOB_FIXTURE["ciphers"][0], "organizationId": "org-a"}, "bwss")
    cipher = gen.encrypt_cipher(src, account, "read/blob", "bwss")
    assert cipher["organizationId"] == "org-a"
    assert gen.open_blob(cipher, account)["content"]["name"] == "Blob bwss"
    with pytest.raises(Exception):
        gen.open_blob({**cipher, "organizationId": None}, account)


def test_blob_fresh_keeps_the_item_key():
    account = gen.load_account("cose-v2")
    src = gen.expand_ns(BLOB_FIXTURE["ciphers"][0], "bwss")
    original = gen.encrypt_cipher(src, account, "read/blob", "bwss")
    fresh = gen.encrypt_cipher(src, account, "read/blob", "bwss", True, src)
    other = gen.encrypt_cipher(src, account, "read/blob", "bwss", True)
    import bwcrypto

    owner = base64.b64decode(account["userKey"])
    key = lambda c: bwcrypto.dec_any(c["key"], owner)  # noqa: E731
    assert key(original) == key(fresh) != key(other)


def test_blob_schemas_accept_the_generated_scenario():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "src" / "read"
        src.mkdir(parents=True)
        (src / "blob.json").write_text(json.dumps(BLOB_FIXTURE), encoding="utf-8")
        files = gen.render_all(Path(d) / "src")
    assert list(files) == ["bwss/read/blob.json"]


def test_security_state_signature_verifies():
    import bwcrypto
    from cryptography.hazmat.primitives.asymmetric import ed25519

    acc = load(ACCOUNTS / "cose-v2.json")
    state = acc["profile"]["accountKeys"]["securityState"]
    verifying = bwcrypto.cbor_decode(base64.b64decode(acc["profile"]["accountKeys"]["signatureKeyPair"]["verifyingKey"]))
    protected, unprotected, payload, sig = bwcrypto.cbor_decode(base64.b64decode(state["securityState"]))
    header = bwcrypto.cbor_decode(protected)
    assert (header[1], header[3], header[4], header[-80000]) == (-8, 60, verifying[2], 2)
    assert unprotected == {}
    ed25519.Ed25519PublicKey.from_public_bytes(verifying[-2]).verify(
        sig, bwcrypto.cbor_encode(["Signature1", protected, b"", payload])
    )
    assert bwcrypto.cbor_decode(payload)["version"] == state["securityVersion"] == 2
    # the signature is over this payload only
    with pytest.raises(Exception):  # noqa: B017
        ed25519.Ed25519PublicKey.from_public_bytes(verifying[-2]).verify(
            sig, bwcrypto.cbor_encode(["Signature1", protected, b"", payload + b"\x00"])
        )


def test_sign1_helper_matches_the_sdk_layout_and_verifies_the_sdk_vector():
    import bwcrypto
    from cryptography.hazmat.primitives.asymmetric import ed25519

    sdk = load(SDK_M3)
    so = bytes.fromhex(sdk["signed_object"]["SIGNED_OBJECT"]["value"])
    vk = bwcrypto.cbor_decode(bytes.fromhex(sdk["signed_object"]["VERIFYING_KEY"]["value"]))
    protected, _, payload, sig = bwcrypto.cbor_decode(so)
    assert bwcrypto.cbor_decode(payload) == sdk["signed_object"]["payload"]
    assert bwcrypto.cbor_decode(protected)[bwcrypto.LABEL_SIGNING_NAMESPACE] == sdk["signed_object"]["namespace"]
    ed25519.Ed25519PublicKey.from_public_bytes(vk[-2]).verify(sig, bwcrypto.cbor_encode(["Signature1", protected, b"", payload]))
    # the SDK's security state parses by the same rules, and our own signer produces the same structure
    state = base64.b64decode(sdk["security_state"]["TEST_SIGNED_SECURITY_STATE"]["value"])
    sdk_protected = bwcrypto.cbor_decode(state)[0]
    mine = bwcrypto.cose_sign1_ed25519(b"\xa0", b"s" * 32, bwcrypto.cbor_decode(sdk_protected)[4], 2)
    assert bwcrypto.cbor_decode(mine)[0] == sdk_protected


def test_cose_v2_unlocks():
    import bwcrypto

    acc = load(ACCOUNTS / "cose-v2.json")
    mk = bwcrypto.master_key(acc["password"], acc["email"], acc["kdf"])
    user_key = bwcrypto.dec_string(acc["profileKey"], bwcrypto.stretch(mk))
    assert user_key == base64.b64decode(acc["userKey"])
    assert bwcrypto.cose_alg(user_key) == bwcrypto.ALG_XAES
    # the signing key is wrapped under the user key and matches the published verifying key
    keys = acc["profile"]["accountKeys"]["signatureKeyPair"]
    signing = bwcrypto.cbor_decode(bwcrypto.cose_decrypt(keys["wrappedSigningKey"], user_key))
    verifying = bwcrypto.cbor_decode(base64.b64decode(keys["verifyingKey"]))
    assert (signing[1], signing[3], signing[4], signing[-1]) == (1, -8, [1], 6)
    assert signing[2] == verifying[2]
    assert len(signing[-4]) == 32
    want_signing, want_verifying = bwcrypto.ed25519_cose_keys(gen.seed_for("cose-v2/signing"), signing[2])
    assert bwcrypto.cbor_encode(signing) == want_signing
    assert base64.b64decode(keys["verifyingKey"]) == want_verifying
    unlock = acc["userDecryption"]["masterPasswordUnlock"]
    assert unlock["kdf"] == {"kdfType": 0, "iterations": 600000}
    assert unlock["masterKeyEncryptedUserKey"] == acc["profileKey"] and unlock["salt"] == acc["email"]
    assert "userDecryption" not in load(ACCOUNTS / "cose.json")


def test_unlock_kdf_covers_argon2id():
    spec = dict(next(a for a in gen.ACCOUNTS if a["name"] == "cose-v2"), kdf=gen.ACCOUNTS[1]["kdf"])
    import bwcrypto

    parts = gen.signed_account_parts(spec, b"s" * 32, bwcrypto.cose_key(b"s" * 32), "2.x")
    assert parts["userDecryption"]["masterPasswordUnlock"]["kdf"] == {
        "kdfType": 1, "iterations": 3, "memory": 64, "parallelism": 4,
    }


def test_secure_note_part_may_be_missing():
    account = gen.load_account("pbkdf2")
    note = {"id": "c1", "type": 2, "name": "Note"}
    enc = lambda src: gen.encrypt_cipher(src, account, "write/x", "bwss")  # noqa: E731
    assert enc(note)["secureNote"] == {"type": 0}
    assert enc({**note, "secureNote": None})["secureNote"] is None
    for bad in ({**note, "type": 1}, {**note, "format": "blob"}):
        with pytest.raises(gen.GenError, match="secureNote needs a type 2 cipher in format fields"):
            enc({**bad, "secureNote": None})


TYPED = {
    "id": "t1",
    "type": 3,
    "name": "Card",
    "card": {"cardholderName": "A B", "number": "4111", "code": None},
    "fields": [{"name": "l", "value": None, "type": 3, "linkedId": 300}],
    "reprompt": 1,
}


def test_typed_parts_round_trip_and_tamper():
    account = gen.load_account("pbkdf2")
    for part, typ, values in (
        ("card", 3, TYPED["card"]),
        ("identity", 4, {"firstName": "Ann", "ssn": None}),
        ("sshKey", 5, {"privateKey": "k", "publicKey": "p", "keyFingerprint": "f"}),
    ):
        src = {k: v for k, v in TYPED.items() if k != "card"} | {"type": typ, part: values}
        cipher = gen.encrypt_cipher(src, account, "open/t", "bwss")
        assert cipher["reprompt"] == 1 and cipher["fields"][0]["linkedId"] == 300
        assert all(v is None or v.startswith("2.") for v in cipher[part].values())
        plain = gen.decrypt(cipher, account)
        assert plain[part] == values and plain["reprompt"] == 1
        assert plain["fields"] == [{"name": "l", "value": None, "type": 3, "linkedId": 300}]
    cipher = gen.encrypt_cipher({**TYPED, "card": None}, account, "open/t", "bwss")
    assert cipher["card"] is None
    tampered = gen.encrypt_cipher({**TYPED, "tamper": ["card.number"]}, account, "open/t", "bwss")
    with pytest.raises(ValueError):
        gen.decrypt(tampered, account)


def test_uri_match_types():
    account = gen.load_account("pbkdf2")
    login = {"username": None, "password": None, "totp": None, "passwordHistory": []}
    uris = ["https://a.invalid", {"uri": "https://b.invalid", "match": 3}]
    src = {"id": "l1", "type": 1, "name": "L", "login": {**login, "uris": uris}}
    cipher = gen.encrypt_cipher(src, account, "open/t", "bwss")
    assert [u["match"] for u in cipher["login"]["uris"]] == [None, 3]
    assert gen.decrypt(cipher, account)["login"]["uris"] == uris
    v2 = gen.load_account("cose-v2")
    blob = gen.encrypt_cipher({**src, "format": "blob"}, v2, "open/t", "bwss")
    assert gen.open_blob(blob, v2)["content"]["typeData"]["uris"] == [
        {"uri": "https://a.invalid", "match": None},
        {"uri": "https://b.invalid", "match": 3},
    ]


def test_typed_blobs_follow_the_sdk_shape():
    account = gen.load_account("cose-v2")
    ssh = {
        "id": "s1",
        "type": 5,
        "name": "S",
        "format": "blob",
        "reprompt": 1,
        "sshKey": {"privateKey": "k", "publicKey": "p", "keyFingerprint": "f"},
    }
    cipher = gen.encrypt_cipher(ssh, account, "open/t", "bwss")
    assert cipher["reprompt"] == 1 and "sshKey" not in cipher
    content = gen.open_blob(cipher, account)["content"]
    assert content["typeData"] == {"type": "sshKey", "privateKey": "k", "publicKey": "p", "fingerprint": "f"}
    card = gen.encrypt_cipher({**TYPED, "format": "blob"}, account, "open/t", "bwss")
    content = gen.open_blob(card, account)["content"]
    assert content["typeData"] == {"type": "card", "cardholderName": "A B", "number": "4111", "code": None}
    assert content["fields"] == [{"name": "l", "value": None, "type": 3, "linkedId": 300}]


def test_folder_names_round_trip_and_tamper():
    for name in ("pbkdf2", "cose"):
        account = gen.load_account(name)
        key = base64.b64decode(account["userKey"])
        out = gen.encrypt_folder({"id": "f", "name": "Work ünï"}, account, "folders/t", "bwss")
        assert out["id"] == "f" and bwcrypto.dec_any(out["name"], key).decode() == "Work ünï"
        assert out == gen.encrypt_folder({"id": "f", "name": "Work ünï"}, account, "folders/t", "bwss")
    account = gen.load_account("pbkdf2")
    bad = gen.encrypt_folder({"id": "f", "name": "x", "tamper": True}, account, "folders/t", "bwss")
    with pytest.raises(ValueError):
        bwcrypto.dec_any(bad["name"], base64.b64decode(account["userKey"]))
    with pytest.raises(gen.GenError, match="COSE"):
        gen.encrypt_folder({"id": "f", "name": "x", "tamper": True}, gen.load_account("cose"), "folders/t", "bwss")
