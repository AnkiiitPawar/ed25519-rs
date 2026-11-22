//! Constant-time helpers.
//!
//! Code that handles secrets must not branch on them or use them as memory
//! indices, because both show up in running time. These helpers turn a
//! secret condition into an all-ones / all-zeros mask, and the callers then
//! blend values with `&`, `|` and `^` instead of `if`.
//!
//! Rust gives no constant-time guarantee: an optimiser is allowed to turn a
//! mask back into a branch. `core::hint::black_box` hides the mask's origin
//! from the optimiser, which in practice stops that, but it is a best-effort
//! hint rather than a promise. The timing experiment in `examples/timing.rs`
//! is how this crate checks the result instead of assuming it.

use core::hint::black_box;

/// All ones if `bit == 1`, all zeros if `bit == 0`. `bit` must be 0 or 1.
#[inline(always)]
pub(crate) fn mask_from_bit(bit: u64) -> u64 {
    black_box(bit).wrapping_neg()
}

/// All ones if `a == b`, all zeros otherwise, without comparing in a branch.
#[inline(always)]
pub(crate) fn eq_mask(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    // For x != 0, x | -x has its top bit set; for x == 0 it is zero.
    let nonzero = (x | x.wrapping_neg()) >> 63;
    mask_from_bit(nonzero ^ 1)
}

/// `true` if the two byte strings are equal. Reads every byte either way.
pub(crate) fn bytes_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(mask_from_bit(0), 0);
        assert_eq!(mask_from_bit(1), u64::MAX);
        assert_eq!(eq_mask(7, 7), u64::MAX);
        assert_eq!(eq_mask(7, 8), 0);
        assert_eq!(eq_mask(0, 1 << 63), 0);
        assert_eq!(eq_mask(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn byte_equality() {
        let a = [3u8; 32];
        let mut b = a;
        assert!(bytes_eq(&a, &b));
        b[31] ^= 0x80;
        assert!(!bytes_eq(&a, &b));
    }
}
