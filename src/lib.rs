//! Ed25519 signatures (RFC 8032) built from first principles: SHA-512, field
//! arithmetic modulo 2^255 - 19, the twisted Edwards group and scalars modulo
//! the group order, with no dependencies and no standard library.
//!
//! **This code has not been audited. It is for study, not for protecting
//! anything real.** Use a maintained library such as `ed25519-dalek`,
//! libsodium or your platform's crypto API for that.
//!
//! ```
//! use ed25519_rs::SigningKey;
//!
//! // In real use the seed must come from a cryptographic random number generator.
//! let key = SigningKey::from_seed(&[7u8; 32]);
//! let signature = key.sign(b"hello");
//! assert!(key.verifying_key().verify(b"hello", &signature).is_ok());
//! assert!(key.verifying_key().verify(b"hellp", &signature).is_err());
//! ```
//!
//! # Three verification rules
//!
//! RFC 8032 allows more than one verification equation, and libraries
//! disagree on edge cases (Chalkias, Garillot, Nikolaenko, "Taming the many
//! EdDSAs", 2020). This crate offers three, and its tests pin down how each
//! behaves on the Wycheproof and ed25519-speccheck edge-case vectors:
//!
//! | method | equation | also rejects |
//! |---|---|---|
//! | [`VerifyingKey::verify`] | `[S]B = R + [k]A` | S ≥ ℓ, non-canonical A or R |
//! | [`VerifyingKey::verify_strict`] | `[S]B = R + [k]A` | the above, plus small-order A or R |
//! | [`VerifyingKey::verify_cofactored`] | `[8][S]B = [8]R + [8][k]A` | S ≥ ℓ, non-canonical A or R |

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod ct;
mod edwards;
mod field;
mod scalar;
pub mod sha512;

use edwards::EdwardsPoint;
use sha512::Sha512;

/// Low-level building blocks, public for the tests, benchmarks and anyone
/// studying the code. None of it is needed to sign or verify, and it is easy
/// to misuse: for example `EdwardsPoint::mul_vartime` leaks its scalar.
pub mod hazmat {
    pub use crate::edwards::EdwardsPoint;
    pub use crate::field::FieldElement;
    /// Arithmetic modulo the group order ℓ.
    pub mod scalar {
        pub use crate::scalar::{is_canonical, mul_add, reduce_wide, L};
    }
}

/// Length of a secret seed in bytes.
pub const SECRET_KEY_LENGTH: usize = 32;
/// Length of an encoded public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// Length of a signature in bytes.
pub const SIGNATURE_LENGTH: usize = 64;

/// Why a key or signature was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A byte string had the wrong length.
    InvalidLength,
    /// The public key is not the canonical encoding of a curve point.
    InvalidPublicKey,
    /// The public key has small order (only `verify_strict` checks this).
    WeakPublicKey,
    /// R is not the canonical encoding of a curve point.
    InvalidR,
    /// R has small order (only `verify_strict` checks this).
    WeakR,
    /// S is not below the group order ℓ, so the signature could be malleable.
    NonCanonicalS,
    /// The verification equation does not hold.
    BadSignature,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidLength => "wrong length",
            Error::InvalidPublicKey => "public key is not a canonical curve point",
            Error::WeakPublicKey => "public key has small order",
            Error::InvalidR => "R is not a canonical curve point",
            Error::WeakR => "R has small order",
            Error::NonCanonicalS => "S is not reduced modulo the group order",
            Error::BadSignature => "signature does not verify",
        })
    }
}

impl core::error::Error for Error {}

/// An Ed25519 signature: the encoded point R followed by the scalar S.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl Signature {
    /// Split 64 bytes into R and S. No checks happen here; verification does them.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> Signature {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Signature { r, s }
    }

    /// Like [`Signature::from_bytes`], but for a slice of unknown length.
    pub fn from_slice(bytes: &[u8]) -> Result<Signature, Error> {
        let array: &[u8; SIGNATURE_LENGTH] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        Ok(Signature::from_bytes(array))
    }

    /// The 64-byte encoding R || S.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }
}

/// k = SHA-512(R || A || M) mod ℓ, the challenge that binds a signature to its message.
fn challenge(r: &[u8; 32], a: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(message);
    scalar::reduce_wide(&h.finalize())
}

/// A public key: a canonical encoding of a curve point, decoded once.
#[derive(Clone, Copy)]
pub struct VerifyingKey {
    bytes: [u8; 32],
    minus_a: EdwardsPoint,
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for VerifyingKey {}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifyingKey(")?;
        for b in &self.bytes {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

impl VerifyingKey {
    /// Decode a public key. Rejects anything that is not the canonical
    /// encoding of a curve point (RFC 8032 section 5.1.3).
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<VerifyingKey, Error> {
        let a = EdwardsPoint::decompress(bytes).ok_or(Error::InvalidPublicKey)?;
        Ok(VerifyingKey {
            bytes: *bytes,
            minus_a: a.neg(),
        })
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.bytes
    }

    /// `true` if the key lies in the 8-element torsion subgroup. Any
    /// signature "verifies" under the identity key, for every message, with
    /// the plain RFC 8032 equation; `verify_strict` refuses such keys.
    pub fn is_weak(&self) -> bool {
        self.minus_a.is_small_order()
    }

    /// `[S]B - [k]A`, which equals R for an honest signature. Checks S < ℓ first.
    fn expected_r(&self, message: &[u8], signature: &Signature) -> Result<EdwardsPoint, Error> {
        if !scalar::is_canonical(&signature.s) {
            return Err(Error::NonCanonicalS);
        }
        let k = challenge(&signature.r, &self.bytes, message);
        Ok(EdwardsPoint::vartime_double_mul_basepoint(
            &k,
            &self.minus_a,
            &signature.s,
        ))
    }

    /// RFC 8032 verification with the cofactorless equation `[S]B = R + [k]A`.
    ///
    /// R is never decoded: `[S]B - [k]A` is encoded and compared byte for byte
    /// with the R in the signature, so a non-canonical R can never match.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let r = self.expected_r(message, signature)?;
        if ct::bytes_eq(&r.compress(), &signature.r) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    /// [`VerifyingKey::verify`], but also rejecting a small-order public key
    /// or R. This closes the "one signature verifies for every message"
    /// trick with torsion keys.
    pub fn verify_strict(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        if self.is_weak() {
            return Err(Error::WeakPublicKey);
        }
        let r = EdwardsPoint::decompress(&signature.r).ok_or(Error::InvalidR)?;
        if r.is_small_order() {
            return Err(Error::WeakR);
        }
        self.verify(message, signature)
    }

    /// RFC 8032 verification with the cofactored equation
    /// `[8][S]B = [8]R + [8][k]A`, computed as `[8]([S]B - [k]A - R) = 0` so
    /// that k is never reduced after the multiplication by 8. Torsion
    /// components are ignored, which makes the outcome the same whatever
    /// shortcut a batch verifier takes.
    pub fn verify_cofactored(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let r = EdwardsPoint::decompress(&signature.r).ok_or(Error::InvalidR)?;
        let expected = self.expected_r(message, signature)?;
        if expected.sub(&r).mul_by_cofactor().is_identity() {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

/// A secret key: the 32-byte seed and the values derived from it.
///
/// The fields are overwritten with zeros when the key is dropped. That is a
/// best effort: copies made on the stack while signing are not wiped.
pub struct SigningKey {
    seed: [u8; 32],
    scalar: [u8; 32],
    prefix: [u8; 32],
    public: VerifyingKey,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifying_key", &self.public)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Expand a 32-byte seed (RFC 8032 section 5.1.5): hash it with SHA-512,
    /// clamp the first half into the secret scalar a, keep the second half
    /// as the nonce prefix, and compute A = [a]B.
    ///
    /// The seed must come from a cryptographically secure random source.
    pub fn from_seed(seed: &[u8; SECRET_KEY_LENGTH]) -> SigningKey {
        let h = sha512::sha512(seed);
        let mut scalar = [0u8; 32];
        let mut prefix = [0u8; 32];
        scalar.copy_from_slice(&h[..32]);
        prefix.copy_from_slice(&h[32..]);
        // Clamping: clear the 3 low bits (a multiple of the cofactor 8),
        // clear bit 255 and set bit 254 (a fixed top bit for the ladder).
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        let a = EdwardsPoint::mul_base(&scalar);
        let public = VerifyingKey {
            bytes: a.compress(),
            minus_a: a.neg(),
        };
        SigningKey {
            seed: *seed,
            scalar,
            prefix,
            public,
        }
    }

    /// The seed this key was made from.
    pub fn seed(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.seed
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.public
    }

    /// Sign a message (RFC 8032 section 5.1.6). Deterministic: the nonce is
    /// r = SHA-512(prefix || M) mod ℓ, so no randomness is needed and the
    /// same key and message always give the same signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut h = Sha512::new();
        h.update(&self.prefix);
        h.update(message);
        let r = scalar::reduce_wide(&h.finalize());
        let big_r = EdwardsPoint::mul_base(&r).compress();
        let k = challenge(&big_r, &self.public.bytes, message);
        // S = r + k·a (mod ℓ)
        let s = scalar::mul_add(&k, &self.scalar, &r);
        Signature { r: big_r, s }
    }
}

/// Overwrite with zeros in a way the optimiser may not remove.
#[allow(unsafe_code)]
fn wipe(bytes: &mut [u8; 32]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference to one byte.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        wipe(&mut self.seed);
        wipe(&mut self.scalar);
        wipe(&mut self.prefix);
    }
}
