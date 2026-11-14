#!/usr/bin/env python3
"""Writes vectors/crypto/totp.json: TOTP known answers (profiles §7), stdlib only.

The codes come from this independent RFC 6238 reference; the RFC 6238 Appendix B rows and the Bitwarden SDK rows
(`sdk-internal` `crates/bitwarden-vault/src/totp.rs` tests) are checked against their published values below, so
the reference is pinned before it writes anything.

    python3 -I vectors/gen/gen_totp.py            # rewrite the file
    python3 -I vectors/gen/gen_totp.py --check    # exit 1 when the file is stale
"""

import base64
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "crypto" / "totp.json"
STEAM = "23456789BCDFGHJKMNPQRTVWXY"
HASHES = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
SEEDS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890" * 6 + b"1234",
}
# RFC 6238 Appendix B, 8 digits: time -> (SHA1, SHA256, SHA512).
RFC6238 = {
    59: ("94287082", "46119246", "90693936"),
    1111111109: ("07081804", "68084774", "25091201"),
    1111111111: ("14050471", "67062674", "99943326"),
    1234567890: ("89005924", "91819424", "93441116"),
    2000000000: ("69279037", "90698825", "38618901"),
    20000000000: ("65353130", "77737706", "47863826"),
}
SDK_TIME = 1672531200  # 2023-01-01T00:00:00Z, the SDK tests' time


def b32(text):
    """The secret of a key text: spaces dropped, uppercased, padding restored."""
    s = text.replace(" ", "").upper().rstrip("=")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def truncate(key, counter, alg):
    h = hmac.new(key, struct.pack(">Q", counter), HASHES[alg]).digest()
    o = h[-1] & 15
    return struct.unpack(">I", h[o : o + 4])[0] & 0x7FFFFFFF


def code(secret, time, alg="SHA1", digits=6, period=30):
    if alg == "STEAM":
        b = truncate(secret, time // period, "SHA1")
        out = ""
        for _ in range(5):
            out += STEAM[b % 26]
            b //= 26
        return out
    return "%0*d" % (digits, truncate(secret, time // period, alg) % 10**digits)


def gen_row(key, time, secret, alg="SHA1", digits=6, period=30, note=None):
    row = {"key": key, "time": time, "code": code(secret, time, alg, digits, period), "secondsRemaining": period - time % period}
    if note:
        row["note"] = note
    return row


def generate_rows():
    rows = []
    for time, codes in RFC6238.items():
        for alg, want in zip(("SHA1", "SHA256", "SHA512"), codes):
            secret = SEEDS[alg]
            key = "otpauth://totp/rfc6238?secret=%s&algorithm=%s&digits=8" % (base64.b32encode(secret).decode(), alg)
            row = gen_row(key, time, secret, alg, 8, note="RFC 6238 Appendix B")
            assert row["code"] == want, (time, alg)
            rows.append(row)
    sdk = [
        ("WQIQ25BRKZYCJVYP", "194506", "SHA1", 30),
        ("wqiq25brkzycjvyp", "194506", "SHA1", 30),
        ("PIUDISEQYA", "829846", "SHA1", 30),
        ("PIUDISEQYA======", "829846", "SHA1", 30),
        ("otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP", "194506", "SHA1", 30),
        ("OTPauth://totp/test-account?secret=WQIQ25BRKZYCJVYP", "194506", "SHA1", 30),
        ("otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP&period=60", "730364", "SHA1", 60),
        ("otpauth://totp/test-account?secret=WQIQ25BRKZYCJVYP&algorithm=SHA256", "842615", "SHA256", 30),
    ]
    for key, want, alg, period in sdk:
        secret = b32(key.split("secret=")[-1].split("&")[0])
        row = gen_row(key, SDK_TIME, secret, alg, 6, period, "Bitwarden SDK test")
        assert row["code"] == want, key
        rows.append(row)
    steam = "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
    for key in ("steam://" + steam, "StEaM://" + steam):
        row = gen_row(key, SDK_TIME, b32(steam), "STEAM", 5, note="Bitwarden SDK test")
        assert row["code"] == "7W6CJ"
        rows.append(row)
    seed = base64.b32encode(SEEDS["SHA1"]).decode()
    rows += [
        gen_row("steam://" + steam, 0, b32(steam), "STEAM", 5),
        gen_row("steam://" + seed, 59, SEEDS["SHA1"], "STEAM", 5),
        gen_row("steam://" + seed, 1234567890, SEEDS["SHA1"], "STEAM", 5),
        gen_row("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", 1234567890, SEEDS["SHA1"], note="rbw: spaces, lowercase"),
        gen_row("otpauth://totp/x?secret=%s&digits=10" % seed, 1234567890, SEEDS["SHA1"], digits=10, note="zero-padded"),
        gen_row("otpauth://totp/x?secret=%s&digits=1" % seed, 59, SEEDS["SHA1"], digits=1),
        gen_row(
            "otpauth://totp/ACME%20Co:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA512&digits=7&period=45",
            1700000000, b32("JBSWY3DPEHPK3PXP"), "SHA512", 7, 45, "every parameter",
        ),
        gen_row("otpauth://totp/x?secret=%s&period=4294967295" % seed, 4294967295 * 3, SEEDS["SHA1"], period=4294967295),
        gen_row("otpauth://totp/x?secret=%s&period=1" % seed, 59, SEEDS["SHA1"], period=1),
        gen_row(seed, 0, SEEDS["SHA1"], note="start of a period"),
    ]
    return rows


def ok(key, secret, alg="SHA1", digits=6, period=30, note=None):
    row = {"key": key, "algorithm": alg, "digits": digits, "period": period, "secret": secret.hex()}
    if note:
        row["note"] = note
    return row


def err(key, error, note=None):
    row = {"key": key, "error": error}
    if note:
        row["note"] = note
    return row


def parse_rows():
    hello = b32("JBSWY3DPEHPK3PXP")
    seed = SEEDS["SHA1"]
    return [
        ok("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", seed, note="bare base32"),
        ok("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", seed, note="spaces, lowercase"),
        ok("  GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n", seed, note="surrounding whitespace"),
        ok("GeZdGnBvGy3tQoJqGeZdGnBvGy3tQoJq", seed, note="mixed case"),
        ok("PIUDISEQYA", b32("PIUDISEQYA"), note="no padding"),
        ok("PIUDISEQYA======", b32("PIUDISEQYA"), note="padding"),
        ok("PIUDISEQYA=", b32("PIUDISEQYA"), note="short padding"),
        ok("PIUDISEQYA = = =", b32("PIUDISEQYA"), note="spaces in the padding"),
        ok("AB", b"\x00", note="one byte"),
        ok("JBSWY3DPEHPK3PXP", hello),
        ok("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example", hello, note="defaults"),
        ok("otpauth://totp?secret=JBSWY3DPEHPK3PXP", hello, note="no label"),
        ok("otpauth://totp/?secret=JBSWY3DPEHPK3PXP", hello, note="empty label"),
        ok(
            "otpauth://totp/ACME%20Co:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA512&digits=8&period=60",
            hello, "SHA512", 8, 60, "every parameter",
        ),
        ok("OTPAUTH://TOTP/x?SECRET=jbswy3dpehpk3pxp&Algorithm=sha256&DIGITS=7&Period=45", hello, "SHA256", 7, 45, "case"),
        ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1", hello, "SHA1"),
        ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP#fragment&digits=12", hello, note="fragment ignored"),
        ok("otpauth://totp/x?secret=JBSW%20Y3DP+EHPK%33PXP", hello, note="percent and plus decoding"),
        ok("otpauth://totp/x?&secret=JBSWY3DPEHPK3PXP&&digits=8&", hello, digits=8, note="empty pairs"),
        ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&image=a%ZZ&counter", hello, note="unknown parameters ignored"),
        ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=1", hello, digits=1),
        ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10", hello, digits=10),
        ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=0008", hello, digits=8, note="leading zeros"),
        ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=1", hello, period=1),
        ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=4294967295", hello, period=4294967295),
        ok("steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ", b32("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"), "STEAM", 5),
        ok("StEaM://hxdm vjec jjws rb3h wizr 4ifu gftm xboz", b32("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"), "STEAM", 5),
        err("", "empty-secret"),
        err("   ", "empty-secret"),
        err("====", "empty-secret"),
        err("steam://", "empty-secret"),
        err("otpauth://totp/x?secret=", "empty-secret"),
        err("otpauth://totp/x?secret", "empty-secret"),
        err("A", "invalid-base32", "length 1 mod 8"),
        err("ABC", "invalid-base32", "length 3 mod 8"),
        err("ABCDEF", "invalid-base32", "length 6 mod 8"),
        err("ABCDEFGHI", "invalid-base32", "length 1 mod 8"),
        err("GEZDGNB1", "invalid-base32", "not in the alphabet"),
        err("GEZDGNBV-GY3TQOJQ", "invalid-base32", "not in the alphabet"),
        err("GE=ZDGNBV", "invalid-base32", "data after padding"),
        err("steam://ABCD123", "invalid-base32"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PX0", "invalid-base32"),
        err("https://example.com/?secret=JBSWY3DPEHPK3PXP", "unsupported-scheme"),
        err("otpauth:totp?secret=JBSWY3DPEHPK3PXP", "unsupported-scheme"),
        err("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "unsupported-type"),
        err("otpauth://?secret=JBSWY3DPEHPK3PXP", "unsupported-type"),
        err("otpauth://totpx/x?secret=JBSWY3DPEHPK3PXP", "unsupported-type"),
        err("otpauth://totp/x", "missing-secret"),
        err("otpauth://totp/x?issuer=Example", "missing-secret"),
        err("otpauth://totp/x?secret=%G1", "malformed-uri"),
        err("otpauth://totp/x?secret=JBSW%4", "malformed-uri"),
        err("otpauth://totp/x?secret=JBSW%", "malformed-uri"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=GEZDGNBV", "duplicate-parameter"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&ALGORITHM=SHA1&algorithm=SHA1", "duplicate-parameter"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6&digits=6", "duplicate-parameter"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=30&period=30", "duplicate-parameter"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "unknown-algorithm"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA-1", "unknown-algorithm"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=", "unknown-algorithm"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=0", "digits-out-of-range"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=11", "digits-out-of-range"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12", "digits-out-of-range"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=256", "digits-out-of-range", "wraps to 0 as a byte"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99999999999999999999999", "digits-out-of-range"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=", "invalid-digits"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=six", "invalid-digits"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=-6", "invalid-digits"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=+6", "invalid-digits"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6.0", "invalid-digits"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0", "period-out-of-range"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=4294967296", "period-out-of-range"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=", "invalid-period"),
        err("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=30s", "invalid-period"),
        err("otpauth://totp/x?digits=12", "digits-out-of-range", "a range error before the missing secret"),
    ]


def build():
    doc = {
        "about": "TOTP known answers: parse a login's totp field, then generate at a unix time. Written by "
        "vectors/gen/gen_totp.py. `secret` is hex; `algorithm` is SHA1, SHA256, SHA512 or STEAM; `error` is the "
        "core's TotpError code.",
        "parse": parse_rows(),
        "generate": generate_rows(),
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def main():
    text = build()
    if sys.argv[1:] == ["--check"]:
        if OUT.read_text(encoding="utf-8") != text:
            print("stale: %s" % OUT)
            sys.exit(1)
        return
    OUT.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
