//! Cross-check against an independent implementation: 50 keys and signatures
//! produced by OpenSSL (via Python `cryptography`, see
//! scripts/openssl_crosscheck.py), with messages of 0 to 2048 bytes chosen to
//! straddle SHA-512 block boundaries.

mod common;
use common::{hex, hex32, lines, to_hex};
use ed25519_rs::{Signature, SigningKey, VerifyingKey};

#[test]
fn keys_and_signatures_match_openssl_byte_for_byte() {
    let text = include_str!("data/openssl_vectors.txt");
    let mut n = 0;
    for line in lines(text) {
        let f: Vec<&str> = line.split(' ').collect();
        let (seed, public, msg, sig) = (hex32(f[0]), f[1], hex(f[2]), f[3]);
        let key = SigningKey::from_seed(&seed);
        assert_eq!(
            to_hex(&key.verifying_key().to_bytes()),
            public,
            "message length {}",
            msg.len()
        );
        let ours = key.sign(&msg);
        assert_eq!(
            to_hex(&ours.to_bytes()),
            sig,
            "message length {}",
            msg.len()
        );
        let vk = VerifyingKey::from_bytes(&hex32(public)).unwrap();
        let theirs = Signature::from_slice(&hex(sig)).unwrap();
        assert!(vk.verify(&msg, &theirs).is_ok());
        n += 1;
    }
    assert_eq!(n, 50);
}
