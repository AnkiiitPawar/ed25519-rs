//! Per-call timings of the main operations, written to docs/bench.json.
//!
//!     cargo run --release --example bench

use ed25519_rs::hazmat::{EdwardsPoint, FieldElement};
use ed25519_rs::sha512::sha512;
use ed25519_rs::{Signature, SigningKey};
use std::hint::black_box;
use std::time::Instant;

/// Median, 10th and 90th percentile of the time per call, in microseconds.
/// Each sample times `batch` consecutive calls, so that operations far
/// shorter than the clock's own overhead (about 20 ns) are still measured.
fn time_once<T>(samples: usize, batch: usize, f: &mut impl FnMut(usize) -> T) -> (f64, f64, f64) {
    for i in 0..samples / 10 * batch {
        black_box(f(i));
    }
    let mut t: Vec<f64> = (0..samples)
        .map(|s| {
            let t0 = Instant::now();
            for i in s * batch..(s + 1) * batch {
                black_box(f(i));
            }
            t0.elapsed().as_nanos() as f64 / batch as f64
        })
        .collect();
    t.sort_unstable_by(f64::total_cmp);
    let q = |p: f64| t[((t.len() - 1) as f64 * p) as usize] / 1000.0;
    (q(0.5), q(0.1), q(0.9))
}

/// The best of three rounds by median: on a shared cloud machine, other
/// tenants can slow a whole round down, but never speed one up.
fn time<T>(samples: usize, batch: usize, mut f: impl FnMut(usize) -> T) -> (f64, f64, f64) {
    (0..3)
        .map(|_| time_once(samples, batch, &mut f))
        .min_by(|a, b| a.0.total_cmp(&b.0))
        .unwrap()
}

fn main() {
    let seeds: Vec<[u8; 32]> = (0..64u8)
        .map(|i| [i.wrapping_mul(37).wrapping_add(1); 32])
        .collect();
    let keys: Vec<SigningKey> = seeds.iter().map(SigningKey::from_seed).collect();
    let msg = [0x42u8; 64];
    let sigs: Vec<Signature> = keys.iter().map(|k| k.sign(&msg)).collect();
    // Public keys serve as arbitrary-looking 256-bit scalars.
    let scalars: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let b = EdwardsPoint::basepoint();
    let fes: Vec<FieldElement> = scalars.iter().map(FieldElement::from_bytes).collect();
    let fe = fes[0];
    let kib = vec![0x5au8; 1024];
    let n = 4000;

    let rows: Vec<(&str, &str, (f64, f64, f64))> = vec![
        (
            "field",
            "multiply",
            time(2000, 1000, |i| fe.mul(&fes[i % 64])),
        ),
        ("field", "invert", time(2000, 10, |i| fes[i % 64].invert())),
        ("hash", "SHA-512, 1 KiB", time(2000, 10, |_| sha512(&kib))),
        (
            "group",
            "[k]B constant time",
            time(n, 1, |i| EdwardsPoint::mul_base(&scalars[i % 64])),
        ),
        (
            "group",
            "[k]B double-and-add",
            time(n, 1, |i| b.mul_vartime(&scalars[i % 64])),
        ),
        (
            "group",
            "[a]A + [b]B (verify)",
            time(n, 1, |i| {
                EdwardsPoint::vartime_double_mul_basepoint(
                    &scalars[i % 64],
                    &b,
                    &scalars[(i + 1) % 64],
                )
            }),
        ),
        (
            "ed25519",
            "key generation",
            time(n, 1, |i| SigningKey::from_seed(&seeds[i % 64])),
        ),
        (
            "ed25519",
            "sign (64-byte message)",
            time(n, 1, |i| keys[i % 64].sign(&msg)),
        ),
        (
            "ed25519",
            "verify",
            time(n, 1, |i| {
                keys[i % 64].verifying_key().verify(&msg, &sigs[i % 64])
            }),
        ),
        (
            "ed25519",
            "verify_strict",
            time(n, 1, |i| {
                keys[i % 64]
                    .verifying_key()
                    .verify_strict(&msg, &sigs[i % 64])
            }),
        ),
        (
            "ed25519",
            "verify_cofactored",
            time(n, 1, |i| {
                keys[i % 64]
                    .verifying_key()
                    .verify_cofactored(&msg, &sigs[i % 64])
            }),
        ),
    ];
    let mut json = String::from("{\"unit\": \"microseconds per call\", \"rows\": [\n");
    for (i, (group, name, (med, p10, p90))) in rows.iter().enumerate() {
        println!("{group:8} {name:26} {med:9.3} µs  (p10 {p10:.3}, p90 {p90:.3})");
        let sep = if i + 1 < rows.len() { "," } else { "" };
        json.push_str(&format!(
            "  {{\"group\": \"{group}\", \"name\": \"{name}\", \"median\": {med:.3}, \"p10\": {p10:.3}, \"p90\": {p90:.3}}}{sep}\n"
        ));
    }
    json.push_str("]}\n");
    std::fs::create_dir_all("docs").unwrap();
    std::fs::write("docs/bench.json", json).unwrap();
    println!("wrote docs/bench.json");
}
