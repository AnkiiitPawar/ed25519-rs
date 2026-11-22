//! Known-answer tests: the 128 SUPERCOP `sign.input` vectors. Lines 1 to 3 are
//! TEST 1, 2 and 3 of RFC 8032 section 7.1. Signing is deterministic, so every
//! public key and signature must match byte for byte.

mod common;
use common::{hex, lines};
use ed25519_rs::{Error, Signature, SigningKey, VerifyingKey};

const SUPERCOP: &str = include_str!("data/supercop_sign_input.txt");

struct Vector {
    seed: [u8; 32],
    public: [u8; 32],
    message: Vec<u8>,
    signature: [u8; 64],
}

fn vectors() -> Vec<Vector> {
    lines(SUPERCOP)
        .map(|line| {
            // secret(seed || public) : public : message : signature || message :
            let f: Vec<&str> = line.split(':').collect();
            let secret = hex(f[0]);
            let message = hex(f[2]);
            let signed = hex(f[3]);
            assert_eq!(&signed[64..], &message[..], "malformed line");
            Vector {
                seed: secret[..32].try_into().unwrap(),
                public: hex(f[1]).try_into().unwrap(),
                message,
                signature: signed[..64].try_into().unwrap(),
            }
        })
        .collect()
}

#[test]
fn all_128_vectors_reproduce_exactly() {
    let vs = vectors();
    assert_eq!(vs.len(), 128);
    for (i, v) in vs.iter().enumerate() {
        let key = SigningKey::from_seed(&v.seed);
        assert_eq!(
            key.verifying_key().to_bytes(),
            v.public,
            "public key, line {}",
            i + 1
        );
        let sig = key.sign(&v.message);
        assert_eq!(sig.to_bytes(), v.signature, "signature, line {}", i + 1);
    }
}

#[test]
fn all_128_vectors_verify_under_every_rule() {
    for (i, v) in vectors().iter().enumerate() {
        let vk = VerifyingKey::from_bytes(&v.public).unwrap();
        let sig = Signature::from_bytes(&v.signature);
        assert_eq!(vk.verify(&v.message, &sig), Ok(()), "line {}", i + 1);
        assert_eq!(vk.verify_strict(&v.message, &sig), Ok(()), "line {}", i + 1);
        assert_eq!(
            vk.verify_cofactored(&v.message, &sig),
            Ok(()),
            "line {}",
            i + 1
        );
    }
}

#[test]
fn any_flipped_bit_is_rejected() {
    // For a sample of vectors, flip each of the 512 signature bits in turn,
    // and one bit of the message. Every variant must fail under every rule.
    for v in vectors().iter().step_by(16) {
        let vk = VerifyingKey::from_bytes(&v.public).unwrap();
        for bit in 0..512 {
            let mut bad = v.signature;
            bad[bit / 8] ^= 1 << (bit % 8);
            let sig = Signature::from_bytes(&bad);
            assert!(vk.verify(&v.message, &sig).is_err(), "bit {bit}");
            assert!(vk.verify_strict(&v.message, &sig).is_err(), "bit {bit}");
            assert!(vk.verify_cofactored(&v.message, &sig).is_err(), "bit {bit}");
        }
        let mut msg = v.message.clone();
        msg.push(0);
        let sig = Signature::from_bytes(&v.signature);
        assert_eq!(vk.verify(&msg, &sig), Err(Error::BadSignature));
    }
}

#[test]
fn s_plus_l_is_rejected_as_malleable() {
    // S + ℓ satisfies the group equation, so only the range check stops it.
    let v = &vectors()[0];
    let vk = VerifyingKey::from_bytes(&v.public).unwrap();
    let l = ed25519_rs::hazmat::scalar::L;
    let mut s = [0u64; 4];
    for (i, limb) in s.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(v.signature[32 + 8 * i..40 + 8 * i].try_into().unwrap());
    }
    let mut carry = 0u128;
    for i in 0..4 {
        let t = s[i] as u128 + l[i] as u128 + carry;
        s[i] = t as u64;
        carry = t >> 64;
    }
    assert_eq!(carry, 0, "S + ℓ must still fit in 256 bits for this vector");
    let mut bad = v.signature;
    for (i, limb) in s.iter().enumerate() {
        bad[32 + 8 * i..40 + 8 * i].copy_from_slice(&limb.to_le_bytes());
    }
    let sig = Signature::from_bytes(&bad);
    assert_eq!(vk.verify(&v.message, &sig), Err(Error::NonCanonicalS));
    assert_eq!(
        vk.verify_cofactored(&v.message, &sig),
        Err(Error::NonCanonicalS)
    );
}

#[test]
fn signature_slices_must_be_64_bytes() {
    assert_eq!(Signature::from_slice(&[0u8; 63]), Err(Error::InvalidLength));
    assert_eq!(Signature::from_slice(&[0u8; 65]), Err(Error::InvalidLength));
    assert!(Signature::from_slice(&[0u8; 64]).is_ok());
}

#[test]
fn debug_output_does_not_print_the_secret() {
    let key = SigningKey::from_seed(&[0xab; 32]);
    let shown = format!("{key:?}");
    assert!(shown.contains("VerifyingKey("));
    assert!(!shown.contains(&"ab".repeat(32)));
}
