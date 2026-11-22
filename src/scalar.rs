//! Integers modulo the group order ℓ = 2^252 + 27742317777372353535851937790883648493.
//!
//! Scalars travel as 32-byte little-endian strings. Reduction is Barrett's
//! method (Handbook of Applied Cryptography, Algorithm 14.42) in base 2^64,
//! written with no branches or memory indices that depend on the value, so
//! it is safe to use on the secret nonce and key.

use crate::ct;

/// ℓ as four 64-bit limbs, least significant first.
pub const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0,
    0x1000000000000000,
];

/// floor(2^512 / ℓ), the Barrett constant (260 bits).
const MU: [u64; 5] = [
    0xed9ce5a30a2c131b,
    0x2106215d086329a7,
    0xffffffffffffffeb,
    0xffffffffffffffff,
    0x000000000000000f,
];

/// Schoolbook multiplication into `out`, truncated to `out.len()` limbs.
/// `out` must start zeroed. Loop bounds depend only on lengths, never on values.
fn mul_into(a: &[u64], b: &[u64], out: &mut [u64]) {
    for (i, &ai) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &bj) in b.iter().enumerate() {
            if i + j >= out.len() {
                break;
            }
            // (2^64-1)² + 2·(2^64-1) = 2^128 - 1: never overflows.
            let t = (ai as u128) * (bj as u128) + (out[i + j] as u128) + (carry as u128);
            out[i + j] = t as u64;
            carry = (t >> 64) as u64;
        }
        if i + b.len() < out.len() {
            out[i + b.len()] = carry;
        }
    }
}

/// `a - b` over five limbs, wrapping modulo 2^320, with the final borrow (0 or 1).
fn sub5(a: &[u64; 5], b: &[u64; 5]) -> ([u64; 5], u64) {
    let mut out = [0u64; 5];
    let mut borrow = 0u64;
    for i in 0..5 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = (b1 | b2) as u64;
    }
    (out, borrow)
}

/// `r - ℓ` if `r >= ℓ`, else `r`, chosen with a mask.
fn conditional_sub_l(r: &[u64; 5]) -> [u64; 5] {
    let (d, borrow) = sub5(r, &[L[0], L[1], L[2], L[3], 0]);
    let keep_r = ct::mask_from_bit(borrow); // a borrow means r < ℓ
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = (r[i] & keep_r) | (d[i] & !keep_r);
    }
    out
}

/// `x mod ℓ` for any `x < 2^512`.
fn barrett(x: &[u64; 8]) -> [u64; 4] {
    // q1 = floor(x / 2^192), q3 = floor(q1·μ / 2^320): an estimate of floor(x / ℓ)
    // that is low by at most 2.
    let q1 = [x[3], x[4], x[5], x[6], x[7]];
    let mut q2 = [0u64; 10];
    mul_into(&q1, &MU, &mut q2);
    let q3 = [q2[5], q2[6], q2[7], q2[8], q2[9]];
    // r = (x - q3·ℓ) mod 2^320, which is the true difference because 0 <= it < 3ℓ.
    let r1 = [x[0], x[1], x[2], x[3], x[4]];
    let mut r2 = [0u64; 5];
    mul_into(&q3, &L, &mut r2);
    let (r, _) = sub5(&r1, &r2);
    let r = conditional_sub_l(&conditional_sub_l(&r));
    [r[0], r[1], r[2], r[3]]
}

fn load<const N: usize>(bytes: &[u8]) -> [u64; N] {
    let mut out = [0u64; N];
    for (limb, chunk) in out.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut w = [0u8; 8];
        w.copy_from_slice(chunk);
        *limb = u64::from_le_bytes(w);
    }
    out
}

fn store(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    out
}

/// Reduce a 64-byte little-endian integer (such as a SHA-512 output) modulo ℓ.
pub fn reduce_wide(bytes: &[u8; 64]) -> [u8; 32] {
    store(&barrett(&load::<8>(bytes)))
}

/// `(a·b + c) mod ℓ` for any 256-bit little-endian `a`, `b` and `c`.
pub fn mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut wide = [0u64; 8];
    mul_into(&load::<4>(a), &load::<4>(b), &mut wide);
    // a·b + c <= (2^256-1)² + 2^256 - 1 < 2^512, so this carry chain cannot overflow.
    let c = load::<4>(c);
    let mut carry = 0u64;
    for (i, w) in wide.iter_mut().enumerate() {
        let addend = if i < 4 { c[i] } else { 0 };
        let t = (*w as u128) + (addend as u128) + (carry as u128);
        *w = t as u64;
        carry = (t >> 64) as u64;
    }
    store(&barrett(&wide))
}

/// `true` if the 32-byte little-endian integer is already below ℓ. RFC 8032
/// requires this of the S half of a signature; without it signatures are
/// malleable (S and S + ℓ would both verify).
pub fn is_canonical(s: &[u8; 32]) -> bool {
    let x = load::<4>(s);
    let (_, borrow) = sub5(&[x[0], x[1], x[2], x[3], 0], &[L[0], L[1], L[2], L[3], 0]);
    borrow == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mu_is_floor_of_2_512_over_l() {
        // μ·ℓ <= 2^512 < (μ + 1)·ℓ. Check via 2^512 - μ·ℓ, computed mod 2^576.
        let mut prod = [0u64; 9];
        mul_into(&MU, &L, &mut prod);
        // 2^512 is limb 8 = 1. Remainder = 2^512 - μ·ℓ must be in [0, ℓ).
        let mut rem = [0u64; 9];
        let mut borrow = 0u64;
        let two512: [u64; 9] = [0, 0, 0, 0, 0, 0, 0, 0, 1];
        for i in 0..9 {
            let (d1, b1) = two512[i].overflowing_sub(prod[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            rem[i] = d2;
            borrow = (b1 | b2) as u64;
        }
        assert_eq!(borrow, 0, "μ·ℓ exceeds 2^512");
        assert!(rem[4..].iter().all(|&w| w == 0));
        let r = [rem[0], rem[1], rem[2], rem[3]];
        assert!(is_canonical(&store(&r)), "remainder not below ℓ");
    }

    #[test]
    fn order_boundaries() {
        let l = store(&L);
        assert!(!is_canonical(&l));
        let mut l_minus_1 = l;
        l_minus_1[0] -= 1;
        assert!(is_canonical(&l_minus_1));
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&l);
        assert_eq!(reduce_wide(&wide), [0u8; 32]);
    }
}
