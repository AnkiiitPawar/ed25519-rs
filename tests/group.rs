//! Group-law properties on pseudo-random points and scalars.

mod common;
use common::Rng;
use ed25519_rs::hazmat::{scalar, EdwardsPoint};

fn point(rng: &mut Rng) -> EdwardsPoint {
    EdwardsPoint::mul_base(&rng.bytes32())
}

#[test]
fn addition_is_associative_and_commutative_with_identity_and_inverses() {
    let mut rng = Rng::new(1);
    for _ in 0..30 {
        let (p, q, r) = (point(&mut rng), point(&mut rng), point(&mut rng));
        assert!(p.add(&q).add(&r).equals(&p.add(&q.add(&r))));
        assert!(p.add(&q).equals(&q.add(&p)));
        assert!(p.add(&EdwardsPoint::IDENTITY).equals(&p));
        assert!(p.add(&p.neg()).is_identity());
        assert!(p.sub(&q).add(&q).equals(&p));
        assert!(p.double().equals(&p.add(&p)));
    }
}

#[test]
fn scalar_multiplication_routines_agree() {
    let mut rng = Rng::new(2);
    for _ in 0..20 {
        let p = point(&mut rng);
        let k = rng.bytes32();
        let ct = p.mul_ct(&k);
        assert!(ct.equals(&p.mul_vartime(&k)));
        let zero = [0u8; 32];
        assert!(ct.equals(&EdwardsPoint::vartime_double_mul_basepoint(&k, &p, &zero)));
    }
}

#[test]
fn scalar_multiplication_distributes() {
    // [a]([b]B) = [a·b mod ℓ]B and [a]B + [c]B = [a + c mod ℓ]B
    let mut rng = Rng::new(3);
    let one = {
        let mut o = [0u8; 32];
        o[0] = 1;
        o
    };
    let zero = [0u8; 32];
    for _ in 0..20 {
        let (a, b, c) = (rng.bytes32(), rng.bytes32(), rng.bytes32());
        let ab = scalar::mul_add(&a, &b, &zero);
        let lhs = EdwardsPoint::mul_base(&b).mul_ct(&a);
        assert!(lhs.equals(&EdwardsPoint::mul_base(&ab)));
        let a_plus_c = scalar::mul_add(&a, &one, &c);
        let sum = EdwardsPoint::mul_base(&a).add(&EdwardsPoint::mul_base(&c));
        assert!(sum.equals(&EdwardsPoint::mul_base(&a_plus_c)));
    }
}

#[test]
fn compression_round_trips() {
    let mut rng = Rng::new(4);
    for _ in 0..50 {
        let p = point(&mut rng);
        let bytes = p.compress();
        let q = EdwardsPoint::decompress(&bytes).expect("a valid encoding");
        assert!(q.equals(&p));
        assert_eq!(q.compress(), bytes);
        // The negation flips only the sign bit.
        let mut neg = bytes;
        neg[31] ^= 0x80;
        assert_eq!(p.neg().compress(), neg);
    }
}
