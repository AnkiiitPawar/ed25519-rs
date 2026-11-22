//! Project Wycheproof's Ed25519 verification vectors (210 cases, Apache-2.0).
//! "valid" must be accepted and "invalid" rejected by every rule. For
//! "acceptable" cases Wycheproof allows either answer, so the policy of each
//! rule is pinned here instead.

mod common;
use common::{hex, lines};
use ed25519_rs::{Error, Signature, VerifyingKey};

const DATA: &str = include_str!("data/wycheproof_ed25519.txt");

struct Case<'a> {
    id: u32,
    result: &'a str,
    flags: Vec<&'a str>,
    public: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fn cases() -> Vec<Case<'static>> {
    lines(DATA)
        .map(|line| {
            let f: Vec<&str> = line.split('|').collect();
            Case {
                id: f[0].parse().unwrap(),
                result: f[1],
                flags: f[2].split(',').collect(),
                public: hex(f[3]),
                message: hex(f[4]),
                signature: hex(f[5]),
            }
        })
        .collect()
}

/// The outcome under (verify, verify_strict, verify_cofactored).
fn outcomes(c: &Case) -> [Result<(), Error>; 3] {
    let key = <[u8; 32]>::try_from(c.public.as_slice())
        .map_err(|_| Error::InvalidLength)
        .and_then(|b| VerifyingKey::from_bytes(&b));
    let sig = Signature::from_slice(&c.signature);
    match (key, sig) {
        (Ok(k), Ok(s)) => [
            k.verify(&c.message, &s),
            k.verify_strict(&c.message, &s),
            k.verify_cofactored(&c.message, &s),
        ],
        (Err(e), _) | (_, Err(e)) => [Err(e); 3],
    }
}

#[test]
fn valid_cases_pass_and_invalid_cases_fail_under_every_rule() {
    let (mut valid, mut invalid) = (0, 0);
    for c in cases() {
        let out = outcomes(&c);
        match c.result {
            "valid" => {
                assert!(
                    out.iter().all(|o| o.is_ok()),
                    "tcId {} {:?}: {out:?}",
                    c.id,
                    c.flags
                );
                valid += 1;
            }
            "invalid" => {
                assert!(
                    out.iter().all(|o| o.is_err()),
                    "tcId {} {:?}: {out:?}",
                    c.id,
                    c.flags
                );
                invalid += 1;
            }
            _ => {}
        }
    }
    assert_eq!((valid, invalid), (117, 64));
}

#[test]
fn acceptable_cases_follow_each_rules_policy() {
    let mut seen = 0;
    for c in cases().iter().filter(|c| c.result == "acceptable") {
        let [plain, strict, cofactored] = outcomes(c);
        if c.flags.contains(&"SmallOrderPublicKey") {
            // The equation holds, so the RFC rules accept; strict refuses the key.
            assert_eq!(plain, Ok(()), "tcId {}", c.id);
            assert_eq!(strict, Err(Error::WeakPublicKey), "tcId {}", c.id);
            assert_eq!(cofactored, Ok(()), "tcId {}", c.id);
        } else {
            assert!(c.flags.contains(&"MixedOrderPublicKey"), "tcId {}", c.id);
            // Mixed-order keys are not small order, and these signatures
            // satisfy even the cofactorless equation, so all rules accept.
            assert_eq!([plain, strict, cofactored], [Ok(()); 3], "tcId {}", c.id);
        }
        seen += 1;
    }
    assert_eq!(seen, 29);
}

#[test]
fn identity_public_key_turns_one_signature_into_a_signature_on_everything() {
    // tcId 152: with A = identity, [k]A vanishes, so [S]B = R does not depend
    // on the message at all. The plain RFC 8032 rule accepts it for any message.
    let c = cases().into_iter().find(|c| c.id == 152).unwrap();
    assert_eq!(c.public[0], 1);
    assert!(
        c.public[1..].iter().all(|&b| b == 0),
        "the identity encodes as 01 00..00"
    );
    let key = VerifyingKey::from_bytes(&c.public.clone().try_into().unwrap()).unwrap();
    let sig = Signature::from_slice(&c.signature).unwrap();
    assert!(key.is_weak());
    for message in [&b""[..], b"pay Mallory 1000", b"any message at all"] {
        assert_eq!(key.verify(message, &sig), Ok(()));
        assert_eq!(key.verify_cofactored(message, &sig), Ok(()));
        assert_eq!(key.verify_strict(message, &sig), Err(Error::WeakPublicKey));
    }
}
