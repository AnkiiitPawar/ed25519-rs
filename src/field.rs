//! Arithmetic in the prime field GF(p), p = 2^255 - 19.
//!
//! An element is five unsigned 51-bit limbs:
//!
//! ```text
//! x = l0 + l1·2^51 + l2·2^102 + l3·2^153 + l4·2^204
//! ```
//!
//! The trick that makes this prime fast is `2^255 ≡ 19 (mod p)`: whatever
//! spills past bit 255 in a product folds back into the bottom limb times 19.
//!
//! Invariant: every element returned by this module has limbs below
//! 2^51 + 2^13. Under that bound each u128 accumulator in `mul` and `square`
//! stays below 2^109 (see `mul`), and the carry that wraps into limb 0 stays
//! below 2^62, so nothing overflows. Every operation re-establishes the
//! bound before returning, including `add`.

use crate::ct;

const MASK: u64 = (1 << 51) - 1;

/// An element of GF(2^255 - 19). The limbs are not unique: compare
/// elements through [`FieldElement::to_bytes`], which is canonical.
#[derive(Clone, Copy, Debug)]
pub struct FieldElement(pub(crate) [u64; 5]);

/// The curve constant d = -121665/121666 (mod p).
pub(crate) const D: FieldElement = FieldElement([
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
]);

/// 2·d, used by point addition.
pub(crate) const D2: FieldElement = FieldElement([
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
]);

/// A square root of -1: 2^((p-1)/4) (mod p).
pub(crate) const SQRT_M1: FieldElement = FieldElement([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);

/// The base point's x coordinate (the even root of the curve equation at y = 4/5).
pub(crate) const BASE_X: FieldElement = FieldElement([
    1738742601995546,
    1146398526822698,
    2070867633025821,
    562264141797630,
    587772402128613,
]);

/// The base point's y coordinate, 4/5 (mod p).
pub(crate) const BASE_Y: FieldElement = FieldElement([
    1801439850948184,
    1351079888211148,
    450359962737049,
    900719925474099,
    1801439850948198,
]);

#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}

/// Propagate carries once around the limbs. Valid for any limbs below 2^58;
/// the result has limbs below 2^51 + 2^13.
#[inline(always)]
fn carry(l: [u64; 5]) -> FieldElement {
    let c0 = l[0] >> 51;
    let c1 = l[1] >> 51;
    let c2 = l[2] >> 51;
    let c3 = l[3] >> 51;
    let c4 = l[4] >> 51;
    FieldElement([
        (l[0] & MASK) + c4 * 19,
        (l[1] & MASK) + c0,
        (l[2] & MASK) + c1,
        (l[3] & MASK) + c2,
        (l[4] & MASK) + c3,
    ])
}

/// Reduce five 128-bit column sums to limbs below 2^51 + 2^13.
#[inline(always)]
fn carry_wide(c0: u128, mut c1: u128, mut c2: u128, mut c3: u128, mut c4: u128) -> FieldElement {
    c1 += c0 >> 51;
    c2 += c1 >> 51;
    c3 += c2 >> 51;
    c4 += c3 >> 51;
    // c4 < 2^109, so the wrap-around carry is below 2^58 and times 19 below 2^63.
    let mut r0 = ((c0 as u64) & MASK) + ((c4 >> 51) as u64) * 19;
    let r1 = ((c1 as u64) & MASK) + (r0 >> 51);
    r0 &= MASK;
    FieldElement([
        r0,
        r1,
        (c2 as u64) & MASK,
        (c3 as u64) & MASK,
        (c4 as u64) & MASK,
    ])
}

impl FieldElement {
    /// 0
    pub const ZERO: FieldElement = FieldElement([0; 5]);
    /// 1
    pub const ONE: FieldElement = FieldElement([1, 0, 0, 0, 0]);

    /// Load 32 little-endian bytes, ignoring the top bit (bit 255).
    /// Values in [p, 2^255) load as they are and behave as their residues.
    pub fn from_bytes(b: &[u8; 32]) -> FieldElement {
        let load = |i: usize| {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(w)
        };
        FieldElement([
            load(0) & MASK,          // bits   0..51
            (load(6) >> 3) & MASK,   // bits  51..102
            (load(12) >> 6) & MASK,  // bits 102..153
            (load(19) >> 1) & MASK,  // bits 153..204
            (load(24) >> 12) & MASK, // bits 204..255
        ])
    }

    /// The unique encoding of the residue in [0, p), as 32 little-endian bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut l = self.0;
        // 1. Carry so limbs 1..4 are below 2^51 and limb 0 below 2^51 + 19.
        //    The value is then below 2^255 + 19 < 2p.
        for i in 0..4 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK;
        }
        l[0] += (l[4] >> 51) * 19;
        l[4] &= MASK;
        // 2. q = 1 exactly when value >= p, i.e. when value + 19 reaches 2^255.
        let mut q = (l[0] + 19) >> 51;
        for limb in &l[1..] {
            q = (limb + q) >> 51;
        }
        // 3. value - q·p = value + 19q - q·2^255: add 19q, carry, drop bit 255.
        l[0] += 19 * q;
        for i in 0..4 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK;
        }
        l[4] &= MASK;
        // 4. Pack the five 51-bit limbs into 255 bits, little-endian.
        let mut out = [0u8; 32];
        let mut acc: u128 = 0;
        let mut bits = 0;
        let mut i = 0;
        for limb in l {
            acc |= (limb as u128) << bits;
            bits += 51;
            while bits >= 8 {
                out[i] = acc as u8;
                acc >>= 8;
                bits -= 8;
                i += 1;
            }
        }
        out[i] = acc as u8;
        out
    }

    /// `self + rhs`
    pub fn add(&self, rhs: &FieldElement) -> FieldElement {
        let (a, b) = (&self.0, &rhs.0);
        carry([
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ])
    }

    /// `self - rhs`. Adds 16p first so no limb can go negative.
    pub fn sub(&self, rhs: &FieldElement) -> FieldElement {
        let (a, b) = (&self.0, &rhs.0);
        // 16p in limb form: 16·(2^51 - 19), then 16·(2^51 - 1) four times.
        const P16_0: u64 = 36028797018963664;
        const P16_N: u64 = 36028797018963952;
        carry([
            (a[0] + P16_0) - b[0],
            (a[1] + P16_N) - b[1],
            (a[2] + P16_N) - b[2],
            (a[3] + P16_N) - b[3],
            (a[4] + P16_N) - b[4],
        ])
    }

    /// `-self`
    pub fn neg(&self) -> FieldElement {
        FieldElement::ZERO.sub(self)
    }

    /// `self · rhs`
    pub fn mul(&self, rhs: &FieldElement) -> FieldElement {
        let (a, b) = (&self.0, &rhs.0);
        // a_i·b_j lands at 2^(51(i+j)); when i + j >= 5 that is 2^255·2^(51(i+j-5)),
        // which is congruent to 19·2^(51(i+j-5)). So pre-multiply b's limbs by 19.
        let b1 = b[1] * 19;
        let b2 = b[2] * 19;
        let b3 = b[3] * 19;
        let b4 = b[4] * 19;
        // With limbs below B = 2^51 + 2^13, each column is below (1 + 4·19)·B² < 2^109.
        let c0 = m(a[0], b[0]) + m(a[4], b1) + m(a[3], b2) + m(a[2], b3) + m(a[1], b4);
        let c1 = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2) + m(a[3], b3) + m(a[2], b4);
        let c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3) + m(a[3], b4);
        let c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4);
        let c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);
        carry_wide(c0, c1, c2, c3, c4)
    }

    /// `self²`: the same columns as `mul`, with equal cross terms merged.
    pub fn square(&self) -> FieldElement {
        let a = &self.0;
        let a0_2 = a[0] * 2;
        let a1_2 = a[1] * 2;
        let a1_38 = a[1] * 38;
        let a2_38 = a[2] * 38;
        let a3_38 = a[3] * 38;
        let a3_19 = a[3] * 19;
        let a4_19 = a[4] * 19;
        let c0 = m(a[0], a[0]) + m(a1_38, a[4]) + m(a2_38, a[3]);
        let c1 = m(a0_2, a[1]) + m(a2_38, a[4]) + m(a3_19, a[3]);
        let c2 = m(a0_2, a[2]) + m(a[1], a[1]) + m(a3_38, a[4]);
        let c3 = m(a0_2, a[3]) + m(a1_2, a[2]) + m(a4_19, a[4]);
        let c4 = m(a0_2, a[4]) + m(a1_2, a[3]) + m(a[2], a[2]);
        carry_wide(c0, c1, c2, c3, c4)
    }

    /// `self^(2^k)`: square k times.
    pub fn pow2k(&self, k: u32) -> FieldElement {
        let mut r = *self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }

    /// Returns `(self^(2^250 - 1), self^11)`, the shared start of `invert` and `pow_p58`.
    fn pow22501(&self) -> (FieldElement, FieldElement) {
        let t0 = self.square(); //                         2
        let t1 = t0.pow2k(2); //                            8
        let t2 = self.mul(&t1); //                          9
        let t3 = t0.mul(&t2); //                           11
        let t4 = t3.square(); //                           22
        let t5 = t2.mul(&t4); //                           31 = 2^5 - 1
        let t7 = t5.pow2k(5).mul(&t5); //                       2^10 - 1
        let t9 = t7.pow2k(10).mul(&t7); //                      2^20 - 1
        let t11 = t9.pow2k(20).mul(&t9); //                     2^40 - 1
        let t13 = t11.pow2k(10).mul(&t7); //                    2^50 - 1
        let t15 = t13.pow2k(50).mul(&t13); //                  2^100 - 1
        let t17 = t15.pow2k(100).mul(&t15); //                 2^200 - 1
        let t19 = t17.pow2k(50).mul(&t13); //                  2^250 - 1
        (t19, t3)
    }

    /// `self^(p-2)`, which is `1/self` for nonzero `self` (Fermat) and 0 for 0.
    pub fn invert(&self) -> FieldElement {
        // p - 2 = 2^255 - 21 = (2^250 - 1)·2^5 + 11
        let (t19, t3) = self.pow22501();
        t19.pow2k(5).mul(&t3)
    }

    /// `self^((p-5)/8)`, the core of the square root used when decoding points.
    pub fn pow_p58(&self) -> FieldElement {
        // (p - 5)/8 = 2^252 - 3 = (2^250 - 1)·4 + 1
        let (t19, _) = self.pow22501();
        t19.pow2k(2).mul(self)
    }

    /// `true` if the canonical value is odd. RFC 8032 calls odd x "negative".
    pub fn is_negative(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// `true` if the value is 0 (mod p).
    pub fn is_zero(&self) -> bool {
        ct::bytes_eq(&self.to_bytes(), &[0u8; 32])
    }

    /// `true` if both represent the same residue.
    pub fn ct_eq(&self, other: &FieldElement) -> bool {
        ct::bytes_eq(&self.to_bytes(), &other.to_bytes())
    }

    /// `b` where `mask` is all ones, `a` where it is all zeros, without branching.
    #[inline(always)]
    pub(crate) fn select(a: &FieldElement, b: &FieldElement, mask: u64) -> FieldElement {
        let mut out = [0u64; 5];
        for (o, (x, y)) in out.iter_mut().zip(a.0.iter().zip(&b.0)) {
            *o = x ^ (mask & (x ^ y));
        }
        FieldElement(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fe(x: u64) -> FieldElement {
        FieldElement([x, 0, 0, 0, 0])
    }

    #[test]
    fn constants_satisfy_their_definitions() {
        // d·121666 = -121665
        assert!(D.mul(&fe(121666)).ct_eq(&fe(121665).neg()));
        assert!(D2.ct_eq(&D.add(&D)));
        assert!(SQRT_M1.square().ct_eq(&FieldElement::ONE.neg()));
        // y = 4/5 and the point lies on -x² + y² = 1 + d·x²·y²
        assert!(BASE_Y.mul(&fe(5)).ct_eq(&fe(4)));
        let (xx, yy) = (BASE_X.square(), BASE_Y.square());
        let lhs = yy.sub(&xx);
        let rhs = FieldElement::ONE.add(&D.mul(&xx).mul(&yy));
        assert!(lhs.ct_eq(&rhs));
        assert!(!BASE_X.is_negative());
    }

    #[test]
    fn encoding_is_canonical() {
        // p itself encodes as 0, and p + 1 as 1.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert_eq!(FieldElement::from_bytes(&p).to_bytes(), [0u8; 32]);
        p[0] = 0xee;
        assert_eq!(
            FieldElement::from_bytes(&p).to_bytes(),
            FieldElement::ONE.to_bytes()
        );
        // The top bit is ignored on load.
        let mut one = [0u8; 32];
        one[0] = 1;
        one[31] = 0x80;
        assert_eq!(
            FieldElement::from_bytes(&one).to_bytes(),
            FieldElement::ONE.to_bytes()
        );
    }

    #[test]
    fn square_matches_mul_on_extreme_limbs() {
        // Limbs at the top of the allowed range exercise the overflow bounds.
        let big = FieldElement([MASK + (1 << 13) - 1; 5]);
        assert!(big.square().ct_eq(&big.mul(&big)));
        let s = big.sub(&FieldElement::ONE).add(&big);
        assert!(s.square().ct_eq(&s.mul(&s)));
    }

    #[test]
    fn inverse_and_square_root_exponents() {
        let x = fe(123456789);
        assert!(x.mul(&x.invert()).ct_eq(&FieldElement::ONE));
        assert!(FieldElement::ZERO.invert().is_zero());
        // (x^((p-5)/8))^8 · x^4 = x^(p-1), which is 1 for nonzero x (Fermat).
        let t = x.pow_p58().pow2k(3);
        let x4 = x.square().square();
        assert!(t.mul(&x4).ct_eq(&FieldElement::ONE));
    }
}
