use super::*;
use serde_json::Value;

fn vectors() -> Value {
    let dir = std::env::var("DYBW_VECTORS_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors").into());
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/crypto/totp.json")).unwrap()).unwrap()
}

fn rows(name: &str) -> Vec<Value> {
    let rows = vectors()[name].as_array().unwrap().clone();
    assert!(!rows.is_empty());
    rows
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn algorithm_name(a: Algorithm) -> &'static str {
    match a {
        Algorithm::Sha1 => "SHA1",
        Algorithm::Sha256 => "SHA256",
        Algorithm::Sha512 => "SHA512",
        Algorithm::Steam => "STEAM",
    }
}

#[test]
fn parse_vectors() {
    for row in rows("parse") {
        let key = row["key"].as_str().unwrap();
        let parsed = TotpKey::parse(key);
        if let Some(error) = row.get("error") {
            let e = parsed.unwrap_err();
            assert_eq!(e.code(), error.as_str().unwrap(), "{key:?}");
            continue;
        }
        let k = parsed.unwrap_or_else(|e| panic!("{key:?}: {e}"));
        assert_eq!(algorithm_name(k.algorithm()), row["algorithm"], "{key:?}");
        assert_eq!(u64::from(k.digits()), row["digits"].as_u64().unwrap(), "{key:?}");
        assert_eq!(u64::from(k.period()), row["period"].as_u64().unwrap(), "{key:?}");
        assert_eq!(hex(&k.secret), row["secret"].as_str().unwrap(), "{key:?}");
    }
}

#[test]
fn generate_vectors() {
    for row in rows("generate") {
        let key = row["key"].as_str().unwrap();
        let code = TotpKey::parse(key).unwrap().generate(row["time"].as_u64().unwrap());
        assert_eq!(code.code(), row["code"].as_str().unwrap(), "{key:?}");
        assert_eq!(code.seconds_remaining(), row["secondsRemaining"].as_u64().unwrap(), "{key:?}");
    }
}

#[test]
fn rfc6238_appendix_b() {
    // RFC 6238 Appendix B, written out here as well so the test does not depend on the vector file alone.
    let seeds = [
        ("SHA1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        ("SHA256", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"),
        (
            "SHA512",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
        ),
    ];
    let table: [(u64, [&str; 3]); 6] = [
        (59, ["94287082", "46119246", "90693936"]),
        (1111111109, ["07081804", "68084774", "25091201"]),
        (1111111111, ["14050471", "67062674", "99943326"]),
        (1234567890, ["89005924", "91819424", "93441116"]),
        (2000000000, ["69279037", "90698825", "38618901"]),
        (20000000000, ["65353130", "77737706", "47863826"]),
    ];
    for (time, codes) in table {
        for ((alg, secret), want) in seeds.iter().zip(codes) {
            let k = TotpKey::parse(&format!("otpauth://totp/r?secret={secret}&algorithm={alg}&digits=8")).unwrap();
            assert_eq!(k.generate(time).code(), want, "{alg} at {time}");
        }
    }
}

#[test]
fn steam_known_answers() {
    // The SDK's test: 2023-01-01T00:00:00Z.
    let k = TotpKey::parse("steam://HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ").unwrap();
    assert_eq!((k.algorithm(), k.digits(), k.period()), (Algorithm::Steam, 5, 30));
    let code = k.generate(1_672_531_200);
    assert_eq!(code.code(), "7W6CJ");
    assert!(code.code().bytes().all(|c| STEAM_ALPHABET.contains(&c)));
}

#[test]
fn seconds_remaining_counts_down_to_the_next_period() {
    let k = TotpKey::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=60").unwrap();
    assert_eq!(k.generate(120).seconds_remaining(), 60);
    assert_eq!(k.generate(121).seconds_remaining(), 59);
    assert_eq!(k.generate(179).seconds_remaining(), 1);
    // The next code is the one at `time + seconds_remaining`, and differs from the current one here.
    let now = k.generate(179);
    let next = k.generate(179 + now.seconds_remaining());
    assert_eq!(next.seconds_remaining(), 60);
    assert_eq!(k.generate(180).code(), next.code());
    assert_eq!(k.generate(u64::MAX).seconds_remaining(), 60 - u64::MAX % 60);
}

#[test]
fn debug_hides_the_secret_and_the_code() {
    let k = TotpKey::parse("JBSWY3DPEHPK3PXP").unwrap();
    let shown = format!("{k:?}");
    assert_eq!(shown, "TotpKey { secret: \"<redacted>\", algorithm: Sha1, digits: 6, period: 30 }");
    let code = k.generate(59);
    let shown = format!("{code:?}");
    assert!(!shown.contains(code.code()), "{shown}");
    assert_eq!(shown, "TotpCode { code: \"<redacted>\", seconds_remaining: 1 }");
}

#[test]
fn errors_name_no_secret_and_give_ranges() {
    let cases = [
        (TotpError::EmptySecret, "the TOTP secret is empty"),
        (TotpError::InvalidBase32, "the TOTP secret is not valid base32"),
        (TotpError::UnsupportedScheme, "the TOTP key is neither base32, an otpauth:// URI nor a steam:// URI"),
        (TotpError::UnsupportedType, "the otpauth URI is not of type totp"),
        (TotpError::MalformedUri, "the otpauth URI is malformed"),
        (TotpError::MissingSecret, "the otpauth URI has no secret"),
        (TotpError::DuplicateParameter("digits"), "the otpauth URI gives the parameter digits more than once"),
        (TotpError::UnknownAlgorithm, "unknown TOTP algorithm: expected SHA1, SHA256 or SHA512"),
        (TotpError::InvalidDigits, "the TOTP digits is not a number"),
        (TotpError::DigitsOutOfRange(12), "the TOTP digits 12 is outside 1..=10"),
        (TotpError::InvalidPeriod, "the TOTP period is not a number"),
        (TotpError::PeriodOutOfRange(0), "the TOTP period 0 is outside 1..=4294967295 seconds"),
    ];
    for (e, text) in cases {
        assert_eq!(e.to_string(), text);
    }
    // Every refused key in the vectors: neither the message nor `Debug` shows the key's text.
    for row in rows("parse").iter().filter(|r| r.get("error").is_some()) {
        let key = row["key"].as_str().unwrap();
        let e = TotpKey::parse(key).unwrap_err();
        for shown in [e.to_string(), format!("{e:?}")] {
            for secret in ["JBSW", "GEZD", "ABCD", "HXDM", "PIUD"] {
                assert!(!shown.contains(secret), "{shown}");
            }
        }
    }
}

#[test]
fn review_focus_digits_12_and_period_0_are_refused() {
    let e = TotpKey::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12").unwrap_err();
    assert_eq!(e, TotpError::DigitsOutOfRange(12));
    let e = TotpKey::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0").unwrap_err();
    assert_eq!(e, TotpError::PeriodOutOfRange(0));
    let e = TotpKey::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99999999999999999999999").unwrap_err();
    assert_eq!(e, TotpError::DigitsOutOfRange(u64::MAX));
}

#[test]
fn a_non_ascii_key_is_refused_without_panicking() {
    // A multi-byte character across the prefix length must not split a UTF-8 sequence.
    assert_eq!(TotpKey::parse("otpauth:/é").unwrap_err(), TotpError::UnsupportedScheme);
    assert_eq!(TotpKey::parse("ééééé").unwrap_err(), TotpError::InvalidBase32);
    assert_eq!(TotpKey::parse("otpauth://totp/é?secret=JBSWY3DPEHPK3PXP").unwrap().digits(), 6);
}

#[test]
fn helpers() {
    assert_eq!(parse_number(b""), None);
    assert_eq!(parse_number(b"18446744073709551616"), Some(u64::MAX));
    assert_eq!(hex_digit(b'f'), Some(15));
    assert_eq!(hex_digit(b'g'), None);
    assert_eq!(truncate(&[]), 0);
    assert_eq!(decimal_code(1_234_567, 10).as_str(), "0001234567");
    for binary in [0, 7, 1_234_567, 0x7fff_ffff] {
        for digits in MIN_DIGITS..=MAX_DIGITS {
            let want = u64::from(binary) % 10u64.pow(u32::from(digits));
            let want = format!("{want:0width$}", width = usize::from(digits));
            assert_eq!(decimal_code(binary, digits).as_str(), want);
        }
    }
}
