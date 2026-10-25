# Independent reference for the MessagePack decoder: encodes values with the
# official msgpack library and records the bytes next to the expected value.
# Expected values use tags JSON cannot express: {"$bin": hex},
# {"$date": epoch milliseconds}, {"$big": decimal string}.
#   uv run --no-project --with msgpack python test/fixtures/gen_msgpack.py
import json, msgpack
from msgpack import Timestamp

cases = []

def case(name, value, expected=None, **opts):
    cases.append({"name": name, "hex": msgpack.packb(value, **opts).hex(), "expected": value if expected is None else expected})

for n in [0, 1, 127, 128, 255, 256, 65535, 65536, 2**32 - 1, 2**32, 2**53 - 1]:
    case(f"uint {n}", n)
for n in [-1, -32, -33, -128, -129, -32768, -32769, -(2**31), -(2**31) - 1, -(2**53) + 1]:
    case(f"int {n}", n)
case("uint64 beyond 2^53", 2**64 - 1, {"$big": str(2**64 - 1)})
case("int64 beyond -2^53", -(2**63), {"$big": str(-(2**63))})
case("float64", 1.5)
case("float32", 0.25, use_single_float=True)
case("nil", None)
case("true", True)
case("false", False)
for n in [0, 31, 32, 255, 256, 70000]:
    case(f"str {n}", "x" * n)
case("str unicode", "Bitwarden ✓ Tiếng Việt 🙂")
case("bin 8", b"\x00\x01\xff", {"$bin": "0001ff"})
case("bin 16", b"\xab" * 300, {"$bin": "ab" * 300})
case("array 15", list(range(15)))
case("array 16", list(range(16)))
case("map 15", {f"k{i}": i for i in range(15)})
case("map 16", {f"k{i}": i for i in range(16)})
case("nested", {"a": [1, {"b": [None, True, "c"]}], "d": {}})
case("timestamp 32", Timestamp(1_700_000_000, 0), {"$date": 1_700_000_000_000})
case("timestamp 64", Timestamp(1_700_000_000, 123_000_000), {"$date": 1_700_000_000_123})
case("timestamp 96", Timestamp(-1, 0), {"$date": -1000})
case("timestamp 96 far future", Timestamp(2**34, 0), {"$date": 2**34 * 1000})

with open("test/fixtures/msgpack.json", "w") as f:
    json.dump(cases, f, indent=1, ensure_ascii=False)
    f.write("\n")
print(f"{len(cases)} cases")
