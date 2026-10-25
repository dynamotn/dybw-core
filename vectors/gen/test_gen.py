"""Tests for the scenario schemas (and, in later commits, the generator)."""

import json
import re
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

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
    listed = set(re.findall(r"^\|\s*`([a-z-]+)`\s*\|", section, re.MULTILINE))
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
