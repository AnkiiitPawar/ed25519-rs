//! Component tests against values computed independently by
//! `scripts/gen_vectors.py` (Python integers and hashlib).

mod common;
use common::{hex32, hex64, lines, to_hex};
use ed25519_rs::hazmat::{scalar, EdwardsPoint, FieldElement};
use ed25519_rs::sha512::{sha512, Sha512};

#[test]
fn sha512_matches_hashlib_for_lengths_0_to_300_and_a_million_a() {
    let text = include_str!("data/sha512_lengths.txt");
    let mut n = 0;
    for line in lines(text) {
        let (len, digest) = line.split_once(' ').unwrap();
        let msg: Vec<u8> = if len == "million-a" {
            vec![b'a'; 1_000_000]
        } else {
            let len: usize = len.parse().unwrap();
            (0..len).map(|i| ((31 * i + 7) % 256) as u8).collect()
        };
        assert_eq!(to_hex(&sha512(&msg)), digest, "length {len}");
        n += 1;
    }
    assert_eq!(n, 302);
}

#[test]
fn sha512_streaming_equals_one_shot_for_every_split() {
    let msg: Vec<u8> = (0..300u32).map(|i| (i * 7 + 1) as u8).collect();
    let whole = sha512(&msg);
    for split in 0..=msg.len() {
        let mut h = Sha512::new();
        h.update(&msg[..split]);
        h.update(&msg[split..]);
        assert_eq!(h.finalize(), whole, "split at {split}");
    }
    // Byte at a time
    let mut h = Sha512::new();
    for b in &msg {
        h.update(core::slice::from_ref(b));
    }
    assert_eq!(h.finalize(), whole);
}

#[test]
fn field_arithmetic_matches_python() {
    let text = include_str!("data/field_vectors.txt");
    let mut n = 0;
    for line in lines(text) {
        let f: Vec<[u8; 32]> = line.split(' ').map(hex32).collect();
        let a = FieldElement::from_bytes(&f[0]);
        let b = FieldElement::from_bytes(&f[1]);
        assert_eq!(a.add(&b).to_bytes(), f[2], "add {line}");
        assert_eq!(a.sub(&b).to_bytes(), f[3], "sub {line}");
        assert_eq!(a.mul(&b).to_bytes(), f[4], "mul {line}");
        assert_eq!(a.square().to_bytes(), f[5], "square {line}");
        assert_eq!(a.invert().to_bytes(), f[6], "invert {line}");
        n += 1;
    }
    assert_eq!(n, 352);
}

#[test]
fn scalar_arithmetic_matches_python() {
    let text = include_str!("data/scalar_vectors.txt");
    let (mut reduces, mut muladds) = (0, 0);
    for line in lines(text) {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "reduce" => {
                assert_eq!(scalar::reduce_wide(&hex64(f[1])), hex32(f[2]), "{line}");
                reduces += 1;
            }
            "muladd" => {
                let r = scalar::mul_add(&hex32(f[1]), &hex32(f[2]), &hex32(f[3]));
                assert_eq!(r, hex32(f[4]), "{line}");
                assert!(scalar::is_canonical(&r));
                muladds += 1;
            }
            other => panic!("unknown line kind {other}"),
        }
    }
    assert_eq!((reduces, muladds), (313, 408));
}

#[test]
fn base_point_multiples_match_python() {
    let text = include_str!("data/mulbase_vectors.txt");
    let mut n = 0;
    for line in lines(text) {
        let (k, expected) = line.split_once(' ').unwrap();
        let k = hex32(k);
        let b = EdwardsPoint::basepoint();
        assert_eq!(
            to_hex(&EdwardsPoint::mul_base(&k).compress()),
            expected,
            "ct k={line}"
        );
        assert_eq!(
            to_hex(&b.mul_vartime(&k).compress()),
            expected,
            "vartime k={line}"
        );
        // [0]P + [k]B through the verification routine as well
        let zero = [0u8; 32];
        let p = EdwardsPoint::vartime_double_mul_basepoint(&zero, &b, &k);
        assert_eq!(to_hex(&p.compress()), expected, "double-mul k={line}");
        n += 1;
    }
    assert_eq!(n, 56);
}

#[test]
fn decompression_matches_python_including_rejections() {
    let text = include_str!("data/decompress_vectors.txt");
    let (mut ok, mut rejected) = (0, 0);
    for line in lines(text) {
        let (input, expected) = line.split_once(' ').unwrap();
        let got = EdwardsPoint::decompress(&hex32(input)).map(|p| to_hex(&p.compress()));
        if expected == "none" {
            assert_eq!(got, None, "{input} should be rejected");
            rejected += 1;
        } else {
            assert_eq!(got.as_deref(), Some(expected), "{input}");
            // Every accepted encoding is canonical: it re-encodes to itself.
            assert_eq!(expected, input);
            ok += 1;
        }
    }
    assert_eq!((ok, rejected), (151, 159));
}

#[test]
fn torsion_subgroup_has_the_expected_structure() {
    let text = include_str!("data/torsion_points.txt");
    let pts: Vec<EdwardsPoint> = lines(text)
        .map(|l| EdwardsPoint::decompress(&hex32(l.split(' ').nth(1).unwrap())).unwrap())
        .collect();
    assert_eq!(pts.len(), 8);
    let t = pts[1];
    for (i, p) in pts.iter().enumerate() {
        assert!(p.is_small_order(), "point {i}");
        // [i]T from repeated addition
        let mut acc = EdwardsPoint::IDENTITY;
        for _ in 0..i {
            acc = acc.add(&t);
        }
        assert!(acc.equals(p), "point {i} is not {i}·T");
    }
    // A prime-order point plus torsion is not small order. Multiplying by ℓ kills
    // the prime-order part and leaves [ℓ mod 8]T = [5]T.
    let mixed = EdwardsPoint::basepoint().add(&t);
    assert!(!mixed.is_small_order());
    let mut l_bytes = [0u8; 32];
    for (c, limb) in l_bytes.chunks_exact_mut(8).zip(scalar::L) {
        c.copy_from_slice(&limb.to_le_bytes());
    }
    assert!(mixed.mul_ct(&l_bytes).equals(&pts[5]));
}
