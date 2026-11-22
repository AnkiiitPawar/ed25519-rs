//! The 12 edge-case vectors of ed25519-speccheck (Chalkias, Garillot,
//! Nikolaenko, "Taming the many EdDSAs", SSR 2020; Apache-2.0). Each targets
//! one place where implementations of RFC 8032 are known to disagree.

mod common;
use common::{hex, lines};
use ed25519_rs::{Error, Signature, VerifyingKey};

const DATA: &str = include_str!("data/speccheck_cases.txt");

use Error::*;

/// Expected (verify, verify_strict, verify_cofactored) for each case.
const EXPECTED: [[Result<(), Error>; 3]; 12] = [
    // 0: S = 0, small-order A and R. Both equations hold; strict refuses A.
    [Ok(()), Err(WeakPublicKey), Ok(())],
    // 1: small-order A, mixed-order R.
    [Ok(()), Err(WeakPublicKey), Ok(())],
    // 2: mixed-order A, small-order R. Strict refuses R.
    [Ok(()), Err(WeakR), Ok(())],
    // 3: mixed A and R, both equations hold: everyone accepts.
    [Ok(()), Ok(()), Ok(())],
    // 4: mixed A and R, only the cofactored equation holds.
    [Err(BadSignature), Err(BadSignature), Ok(())],
    // 5: like 4, and it fails a cofactored check that pre-reduces 8k mod ℓ.
    //    verify_cofactored multiplies by 8 last, so it accepts.
    [Err(BadSignature), Err(BadSignature), Ok(())],
    // 6, 7: S >= ℓ (malleability). The range check rejects before any maths.
    [Err(NonCanonicalS), Err(NonCanonicalS), Err(NonCanonicalS)],
    [Err(NonCanonicalS), Err(NonCanonicalS), Err(NonCanonicalS)],
    // 8, 9: R is (0, -1) encoded with the sign bit set. Never equal to a
    //    computed encoding, and refused by the decoder.
    [Err(BadSignature), Err(InvalidR), Err(InvalidR)],
    [Err(BadSignature), Err(InvalidR), Err(InvalidR)],
    // 10, 11: the public key is the same non-canonical encoding.
    [
        Err(InvalidPublicKey),
        Err(InvalidPublicKey),
        Err(InvalidPublicKey),
    ],
    [
        Err(InvalidPublicKey),
        Err(InvalidPublicKey),
        Err(InvalidPublicKey),
    ],
];

#[test]
fn every_case_gets_the_documented_answer_under_every_rule() {
    let mut n = 0;
    for line in lines(DATA) {
        let f: Vec<&str> = line.split('|').collect();
        let i: usize = f[0].parse().unwrap();
        let (pk, msg, sig) = (hex(f[1]), hex(f[2]), hex(f[3]));
        let got = match VerifyingKey::from_bytes(&pk.try_into().unwrap()) {
            Err(e) => [Err(e); 3],
            Ok(key) => {
                let sig = Signature::from_slice(&sig).unwrap();
                [
                    key.verify(&msg, &sig),
                    key.verify_strict(&msg, &sig),
                    key.verify_cofactored(&msg, &sig),
                ]
            }
        };
        assert_eq!(got, EXPECTED[i], "case {i}");
        n += 1;
    }
    assert_eq!(n, 12);
}
