//! The Ed25519 group: points on the twisted Edwards curve
//!
//! ```text
//! -x² + y² = 1 + d·x²·y²   over GF(2^255 - 19),   d = -121665/121666
//! ```
//!
//! Points are kept in extended coordinates (X : Y : Z : T) with x = X/Z,
//! y = Y/Z and x·y = T/Z (Hisil, Wong, Carter, Dawson 2008), which avoids a
//! field inversion on every operation. The addition formula is the one in
//! RFC 8032 section 5.1.4. For this curve it is complete: it gives the right
//! answer for every pair of inputs, including doubling and the identity, so
//! the scalar multiplications below never need a special case.
//!
//! The group has order 8·ℓ. The base point B generates the subgroup of prime
//! order ℓ; the other factor of 8 is the "torsion" that the verification
//! modes in `lib.rs` treat differently.

use crate::ct;
use crate::field::{FieldElement, BASE_X, BASE_Y, D, D2, SQRT_M1};

/// A point on the curve in extended coordinates.
#[derive(Clone, Copy, Debug)]
pub struct EdwardsPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

/// Nibble `i` (0 = least significant) of a 256-bit little-endian scalar.
#[inline(always)]
fn nibble(k: &[u8; 32], i: usize) -> u8 {
    (k[i / 2] >> ((i % 2) * 4)) & 0x0f
}

impl EdwardsPoint {
    /// The neutral element (0, 1).
    pub const IDENTITY: EdwardsPoint = EdwardsPoint {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// The standard base point B, with y = 4/5 and even x.
    pub fn basepoint() -> EdwardsPoint {
        EdwardsPoint {
            x: BASE_X,
            y: BASE_Y,
            z: FieldElement::ONE,
            t: BASE_X.mul(&BASE_Y),
        }
    }

    /// `self + other` (RFC 8032 section 5.1.4; 9 field multiplications).
    pub fn add(&self, other: &EdwardsPoint) -> EdwardsPoint {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&D2).mul(&other.t);
        let d = self.z.add(&self.z).mul(&other.z);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// `2·self` (RFC 8032 section 5.1.4; 4 squarings and 4 multiplications).
    pub fn double(&self) -> EdwardsPoint {
        let a = self.x.square();
        let b = self.y.square();
        let zz = self.z.square();
        let c = zz.add(&zz);
        let h = a.add(&b);
        let e = h.sub(&self.x.add(&self.y).square());
        let g = a.sub(&b);
        let f = c.add(&g);
        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// `-self`: (x, y) becomes (-x, y).
    pub fn neg(&self) -> EdwardsPoint {
        EdwardsPoint {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// `self - other`
    pub fn sub(&self, other: &EdwardsPoint) -> EdwardsPoint {
        self.add(&other.neg())
    }

    /// `8·self`, which removes any torsion component.
    pub fn mul_by_cofactor(&self) -> EdwardsPoint {
        self.double().double().double()
    }

    /// `true` for the identity: X = 0 and Y = Z.
    pub fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.ct_eq(&self.z)
    }

    /// `true` if `8·self` is the identity, i.e. the point lies in the
    /// eight-element torsion subgroup. Such keys and nonces are "weak".
    pub fn is_small_order(&self) -> bool {
        self.mul_by_cofactor().is_identity()
    }

    /// `true` if both are the same point (compares X/Z and Y/Z).
    pub fn equals(&self, other: &EdwardsPoint) -> bool {
        self.x.mul(&other.z).ct_eq(&other.x.mul(&self.z))
            && self.y.mul(&other.z).ct_eq(&other.y.mul(&self.z))
    }

    /// Encode as 32 bytes: y in little-endian, with the sign (parity) of x in bit 255.
    pub fn compress(&self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let mut s = y.to_bytes();
        s[31] |= (x.is_negative() as u8) << 7;
        s
    }

    /// Decode 32 bytes (RFC 8032 section 5.1.3). Fails if y is not below p,
    /// if no x exists for this y, or if x = 0 but the sign bit is set: every
    /// point therefore has exactly one accepted encoding.
    pub fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
        let y = FieldElement::from_bytes(bytes);
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        if y.to_bytes() != y_bytes {
            return None; // y >= p
        }
        let sign = bytes[31] >> 7 == 1;
        // x² = (y² - 1) / (d·y² + 1) = u / v. The denominator is never 0 on this curve.
        let yy = y.square();
        let u = yy.sub(&FieldElement::ONE);
        let v = yy.mul(&D).add(&FieldElement::ONE);
        // Candidate root x = (u/v)^((p+3)/8), computed as u·v³·(u·v⁷)^((p-5)/8).
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
        let vxx = v.mul(&x.square());
        if vxx.ct_eq(&u) {
            // x² = u/v already
        } else if vxx.ct_eq(&u.neg()) {
            x = x.mul(&SQRT_M1); // x² was -u/v; multiplying by √-1 fixes the sign
        } else {
            return None; // u/v is not a square: this y is not on the curve
        }
        if x.is_zero() && sign {
            return None;
        }
        if x.is_negative() != sign {
            x = x.neg();
        }
        Some(EdwardsPoint {
            x,
            y,
            z: FieldElement::ONE,
            t: x.mul(&y),
        })
    }

    /// `[0]P, [1]P, ..., [15]P`
    fn multiples(&self) -> [EdwardsPoint; 16] {
        let mut table = [EdwardsPoint::IDENTITY; 16];
        for i in 1..16 {
            table[i] = table[i - 1].add(self);
        }
        table
    }

    /// `b` where `mask` is all ones, `a` where it is all zeros.
    #[inline(always)]
    fn select(a: &EdwardsPoint, b: &EdwardsPoint, mask: u64) -> EdwardsPoint {
        EdwardsPoint {
            x: FieldElement::select(&a.x, &b.x, mask),
            y: FieldElement::select(&a.y, &b.y, mask),
            z: FieldElement::select(&a.z, &b.z, mask),
            t: FieldElement::select(&a.t, &b.t, mask),
        }
    }

    /// `table[index]`, reading all sixteen entries so the memory access
    /// pattern does not depend on `index`.
    fn ct_lookup(table: &[EdwardsPoint; 16], index: u8) -> EdwardsPoint {
        let mut r = EdwardsPoint::IDENTITY;
        for (j, entry) in table.iter().enumerate() {
            r = EdwardsPoint::select(&r, entry, ct::eq_mask(j as u64, index as u64));
        }
        r
    }

    /// `[k]P` in constant time, for secret `k` (any 256-bit little-endian integer).
    ///
    /// Fixed 4-bit window: per nibble, four doublings and one addition of a
    /// table entry fetched by `ct_lookup`. The sequence of operations and
    /// memory accesses is the same for every `k`.
    pub fn mul_ct(&self, k: &[u8; 32]) -> EdwardsPoint {
        let table = self.multiples();
        let mut acc = EdwardsPoint::IDENTITY;
        for i in (0..64).rev() {
            acc = acc.double().double().double().double();
            acc = acc.add(&EdwardsPoint::ct_lookup(&table, nibble(k, i)));
        }
        acc
    }

    /// `[k]B` in constant time.
    pub fn mul_base(k: &[u8; 32]) -> EdwardsPoint {
        EdwardsPoint::basepoint().mul_ct(k)
    }

    /// `[k]P` by textbook double-and-add, which adds only for 1 bits and so
    /// takes longer for scalars with more 1 bits. It leaks `k` through timing
    /// and is kept only as the counter-example in `examples/timing.rs`.
    pub fn mul_vartime(&self, k: &[u8; 32]) -> EdwardsPoint {
        let mut acc = EdwardsPoint::IDENTITY;
        for i in (0..256).rev() {
            acc = acc.double();
            if (k[i / 8] >> (i % 8)) & 1 == 1 {
                acc = acc.add(self);
            }
        }
        acc
    }

    /// `[a]P + [b]B` for public scalars, as needed by verification.
    ///
    /// Straus's method: both scalars share one chain of doublings, with a
    /// 4-bit window for each. Variable time, so never use it with secrets.
    pub fn vartime_double_mul_basepoint(
        a: &[u8; 32],
        p: &EdwardsPoint,
        b: &[u8; 32],
    ) -> EdwardsPoint {
        let table_p = p.multiples();
        let table_b = EdwardsPoint::basepoint().multiples();
        let mut acc = EdwardsPoint::IDENTITY;
        for i in (0..64).rev() {
            acc = acc.double().double().double().double();
            let (na, nb) = (nibble(a, i), nibble(b, i));
            if na != 0 {
                acc = acc.add(&table_p[na as usize]);
            }
            if nb != 0 {
                acc = acc.add(&table_b[nb as usize]);
            }
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_point_encoding() {
        // RFC 8032: B encodes as 0x58 followed by 0x66 thirty-one times.
        let mut expected = [0x66u8; 32];
        expected[0] = 0x58;
        assert_eq!(EdwardsPoint::basepoint().compress(), expected);
    }

    #[test]
    fn doubling_agrees_with_addition() {
        let mut p = EdwardsPoint::basepoint();
        for _ in 0..20 {
            assert!(p.double().equals(&p.add(&p)));
            p = p.double().add(&EdwardsPoint::basepoint());
        }
        assert!(EdwardsPoint::IDENTITY.double().is_identity());
    }

    #[test]
    fn base_point_has_order_l() {
        let l = crate::scalar::L;
        let mut k = [0u8; 32];
        for (chunk, limb) in k.chunks_exact_mut(8).zip(l) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        assert!(EdwardsPoint::mul_base(&k).is_identity());
        assert!(EdwardsPoint::basepoint().mul_vartime(&k).is_identity());
        assert!(!EdwardsPoint::basepoint().is_small_order());
    }
}
