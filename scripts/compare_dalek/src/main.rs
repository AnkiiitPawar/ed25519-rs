//! Same measurement as examples/bench.rs, applied to ed25519-dalek.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use std::hint::black_box;
use std::time::Instant;

/// Best of three rounds of the median single-call time, as in examples/bench.rs.
fn median_us<T>(iters: usize, mut f: impl FnMut(usize) -> T) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..3 {
        for i in 0..iters / 10 {
            black_box(f(i));
        }
        let mut t: Vec<u64> = (0..iters)
            .map(|i| {
                let t0 = Instant::now();
                black_box(f(i));
                t0.elapsed().as_nanos() as u64
            })
            .collect();
        t.sort_unstable();
        best = best.min(t[t.len() / 2] as f64 / 1000.0);
    }
    best
}

fn main() {
    let seeds: Vec<[u8; 32]> = (0..64u8).map(|i| [i.wrapping_mul(37).wrapping_add(1); 32]).collect();
    let keys: Vec<SigningKey> = seeds.iter().map(SigningKey::from_bytes).collect();
    let msg = [0x42u8; 64];
    let sigs: Vec<Signature> = keys.iter().map(|k| k.sign(&msg)).collect();
    let n = 4000;
    let rows = [
        ("key generation", median_us(n, |i| SigningKey::from_bytes(&seeds[i % 64]).verifying_key())),
        ("sign (64-byte message)", median_us(n, |i| keys[i % 64].sign(&msg))),
        ("verify", median_us(n, |i| keys[i % 64].verifying_key().verify(&msg, &sigs[i % 64]))),
        ("verify_strict", median_us(n, |i| keys[i % 64].verifying_key().verify_strict(&msg, &sigs[i % 64]))),
    ];
    let body: Vec<String> = rows.iter().map(|(k, v)| format!("    \"{k}\": {v:.3}")).collect();
    let json = format!(
        "{{\n  \"library\": \"ed25519-dalek 2.2.0 (default features)\",\n  \"unit\": \"microseconds per call (median)\",\n  \"rows\": {{\n{}\n  }}\n}}\n",
        body.join(",\n")
    );
    println!("{json}");
    std::fs::write("../../docs/bench_dalek.json", json).unwrap();
}
