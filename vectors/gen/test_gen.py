"""Tests for the scenario schemas (and, in later commits, the generator)."""

import json
import re
from pathlib import Path

import jsonschema
import pytest

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


def test_source_schema_accepts_minimal():
    jsonschema.validate(MINIMAL, load(SOURCE_SCHEMA))


def test_source_schema_rejects_unknown_key():
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**MINIMAL, "foo": 1}, load(SOURCE_SCHEMA))


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


@pytest.mark.parametrize("path", [SOURCE_SCHEMA, SCENARIO_SCHEMA])
def test_reason_codes_listed(path):
    enums = reason_enums(load(path))
    assert enums, "schema defines no reason enum"
    readme = README.read_text(encoding="utf-8")
    listed = set(re.findall(r"^\|\s*`([a-z-]+)`\s*\|", readme, re.MULTILINE))
    for codes in enums:
        assert set(codes) <= listed, set(codes) - listed


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
    jsonschema.validate(generated(cipher), load(SCENARIO_SCHEMA))


def test_scenario_schema_rejects_plaintext_name():
    bad = {"id": "c1", "type": 1, "name": "plain"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(generated(bad), load(SCENARIO_SCHEMA))


def test_source_schema_accepts_later_shapes():
    src = {**MINIMAL, "namespaces": ["obsidian"],
           "device": {"base": {"a": {"cipher": "c", "revisionDate": "2026-01-01T00:00:00Z", "value": "v"}},
                      "pendingCreates": []},
           "local": {"a": None},
           "operation": {"kind": "set-value", "id": "a", "value": "v",
                         "fresh": {"id": "c", "type": 1, "name": "n"}},
           "expect": {"write": {"requests": [{"method": "trash", "cipher": "c"}]},
                      "plan": [{"kind": "conflict", "id": "a", "conflict": "both-changed"}]}}
    jsonschema.validate(src, load(SOURCE_SCHEMA))
    src["expect"]["plan"][0]["conflict"] = "nope"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(src, load(SOURCE_SCHEMA))
