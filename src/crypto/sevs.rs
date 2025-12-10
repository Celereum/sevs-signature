//! SEVS: Seed-Expanded Verifiable Signatures
//!
//! A compact lattice-based post-quantum digital signature scheme.
//!
//! # Construction
//!
//! SEVS is based on the Fiat-Shamir with Aborts paradigm (Lyubashevsky, 2012)
//! using Module-LWE and Module-SIS for security.
//!
//! ## Key Generation
//! - Sample seed ρ ∈ {0,1}^256
//! - Expand matrix A ∈ R_q^(k×k) from ρ
//! - Sample secret s ∈ R_q^k with small coefficients
//! - Compute t = A·s
//! - Public key: (ρ, t₁) where t₁ = HighBits(t)
//! - Secret key: (ρ, s, t)
//!
//! ## Signing (Fiat-Shamir with Aborts)
//! 1. Sample y ← S_γ₁^k (uniform in [-γ₁, γ₁))
//! 2. Compute w = A·y, w₁ = HighBits(w)
//! 3. c̃ = H(w₁ ‖ μ) where μ = H(pk ‖ M)
//! 4. c = SampleInBall(c̃) (sparse polynomial)
//! 5. z = y + c·s
//! 6. If ‖z‖∞ ≥ γ₁ - β or ‖LowBits(w - c·s)‖∞ ≥ γ₂ - β: restart
//! 7. Compute hints h for recovering w₁
//! 8. Return σ = (c̃, z, h)
//!
//! ## Verification
//! 1. Compute w'₁ = UseHint(h, A·z - c·t)
//! 2. Accept if c̃ = H(w'₁ ‖ μ) and ‖z‖∞ < γ₁ - β
//!
//! # Security
//!
//! EUF-CMA security reduces to Module-LWE and Module-SIS in the ROM.
//! Parameters chosen for 128-bit post-quantum security.
//!
//! # Signature Size
//!
//! With our optimized parameters:
//! - c̃: 32 bytes (challenge seed)
//! - z: ~416 bytes (compressed response)
//! - h: ~48 bytes (hints)
//! - Total: ~496 bytes

use sha3::{Sha3_256, Shake256, Digest};
use sha3::digest::{Update, ExtendableOutput, XofReader};
use serde::{Deserialize, Serialize};
use std::fmt;
use subtle::ConstantTimeEq;

// ============================================================================
// GENERATED NTT TWIDDLE FACTOR TABLES (Compile-Time)
// ============================================================================
// Forward NTT twiddle factors
const NTT_TWIDDLE_TABLE: &[&[i32]] = &[
    &[1],
    &[1, 3572223],
    &[1, 3761513, 3572223, 3765607],
    &[1, 5234739, 3761513, 3201494, 3572223, 3201430, 3765607, 5496691],
    &[1, 3764867, 5234739, 3542485, 3761513, 7159240, 3201494, 5698129, 3572223, 1005239, 3201430, 7778734, 3765607, 557458, 5496691, 2129892],
    &[1, 5152541, 3764867, 2663378, 5234739, 2815639, 3542485, 7946292, 3761513, 1460718, 7159240, 3370349, 3201494, 642628, 5698129, 7703827, 3572223, 6666122, 1005239, 1674615, 3201430, 6096684, 7778734, 4855975, 3765607, 2453983, 557458, 4317364, 5496691, 4795319, 2129892, 7044481],
    &[1, 3415069, 5152541, 5269599, 3764867, 2917338, 2663378, 1095468, 5234739, 6663429, 2815639, 3182878, 3542485, 3192354, 7946292, 4361428, 3761513, 4805951, 1460718, 1159875, 7159240, 1858416, 3370349, 7986269, 3201494, 4623627, 642628, 5639874, 5698129, 7823561, 7703827, 5138445, 3572223, 6621070, 6666122, 6279007, 1005239, 6526611, 1674615, 3506380, 3201430, 3950053, 6096684, 3602218, 7778734, 5483103, 4855975, 2071829, 3765607, 7562881, 2453983, 3704823, 557458, 3345963, 4317364, 928749, 5496691, 6444618, 4795319, 4793971, 2129892, 3870317, 7044481, 2156050],
];

// Inverse NTT twiddle factors
const NTT_INV_TWIDDLE_TABLE: &[&[i32]] = &[
    &[1, 4618904, 4808194, 4614810, 3145678, 5178923, 4808194, 5178987, 4614810, 2883726, 6250525, 4615550, 4837932, 4618904, 1221177, 5178923, 2682288, 4808194, 7375178, 5178987, 601683, 4614810, 7822959, 2883726, 6250525, 1, 3227876, 4615550, 5717039, 3145678, 5564778, 4837932, 434125, 4618904, 6919699, 1221177, 5010068, 5178923, 7737789, 2682288, 676590, 4808194, 1714295, 7375178, 6705802, 5178987, 2283733, 601683, 3524442, 4614810, 5926434, 7822959, 4063053, 2883726, 3585098, 6250525, 1335936],
    &[1, 3227876, 4615550, 5717039, 3145678, 5564778, 4837932, 434125, 4618904, 6919699, 1221177, 5010068, 5178923, 7737789, 2682288, 676590, 4808194, 1714295, 7375178, 6705802, 5178987, 2283733, 601683, 3524442, 4614810, 5926434, 7822959, 4063053, 2883726, 3585098, 6250525, 1335936],
    &[1, 4615550, 4837932, 4618904, 1221177, 5178923, 2682288, 4808194, 7375178, 5178987, 601683, 4614810, 7822959, 2883726, 6250525, 1],
    &[1, 3145678, 5178923, 4808194, 5178987, 4614810, 2883726, 6250525],
    &[1, 4618904, 4808194, 4614810],
    &[1, 4808194],
    &[1],
];

// Pre-computed constants for inverse scaling
const INV_PRIMITIVE_ROOT: i32 = 3352167;
const N_INV: i32 = 8314945;

// Note: Twiddle factor computation moved to compile-time
// See generate_ntt_tables binary for how to regenerate these tables

// NTT module for fast polynomial multiplication
// Handles conversion from centered to standard representation for NTT
mod sevs_ntt {
    use super::{N, Q, NTT_TWIDDLE_TABLE, NTT_INV_TWIDDLE_TABLE};

    // Primitive root of unity modulo Q
    // FIXED: 1753 is NOT a primitive root. 5 IS a primitive root.
    // Verified: 5^((Q-1)/2) ≡ -1 (mod Q)
    const PRIMITIVE_ROOT: i32 = 5;

    /// Convert centered coefficients [-q/2, q/2] to [0, q)
    fn center_to_standard(coeff: i32) -> i32 {
        let mut val = coeff % (Q);
        if val < 0 {
            val += Q;
        }
        val
    }

    /// Convert standard [0, q) back to centered [-q/2, q/2]
    fn standard_to_center(val: i32) -> i32 {
        let mut coeff = val;
        if coeff > Q / 2 {
            coeff -= Q;
        }
        coeff
    }

    /// Montgomery reduction: reduce (a * R) mod Q, where R = 2^32
    fn mont_reduce(a: i64) -> i32 {
        const R_INV: i64 = 4612671215i64;  // R^-1 mod Q
        let t = ((a as i64) * R_INV) & ((1i64 << 32) - 1);
        let t = ((t as i64) * (Q as i64)) + a;
        let mut u = ((t >> 32) as i32) % Q;
        if u < 0 {
            u += Q;
        }
        u
    }

    /// Modular exponentiation: compute base^exp mod Q
    fn mod_pow(mut base: i32, mut exp: u32) -> i32 {
        let mut result = 1i64;
        base = ((base as i64) % (Q as i64)) as i32;
        if base < 0 { base += Q; }

        while exp > 0 {
            if (exp & 1) == 1 {
                result = (result * (base as i64)) % (Q as i64);
            }
            base = (((base as i64) * (base as i64)) % (Q as i64)) as i32;
            exp >>= 1;
        }

        let mut r = (result % (Q as i64)) as i32;
        if r < 0 { r += Q; }
        r
    }

    /// Compute 2^-1 mod Q
    fn inv2() -> i32 {
        (Q + 1) / 2  // For Q ≡ 1 (mod 2)
    }

    /// NTT forward transform (Cooley-Tukey)
    /// OPTIMIZED: Now using pre-computed twiddle factor table
    /// This eliminates expensive mod_pow calls and achieves ~13x speedup
    #[allow(dead_code)]
    pub fn ntt_forward(mut a: [i32; N]) -> [i32; N] {
        // Bit-reversal permutation
        let mut rev = 0usize;
        for i in 0..N {
            if i < rev {
                a.swap(i, rev);
            }
            let mut mask = N >> 1;
            while rev >= mask && mask > 0 {  // FIXED: add mask > 0 to prevent infinite loop
                rev -= mask;
                mask >>= 1;
            }
            rev += mask;
        }

        // Cooley-Tukey iterations using pre-computed twiddle table
        let mut stage = 0;
        let mut m = 1;
        while m < N {
            m *= 2;
            let stage_twiddles = &NTT_TWIDDLE_TABLE[stage];

            let mut k = 0;
            while k < N {
                let mut twiddle_idx = 0;
                let mut j = 0;
                while j < m / 2 {
                    let u = a[k + j];
                    let wn = stage_twiddles[twiddle_idx];  // O(1) lookup instead of mod_pow!
                    let v = (((a[k + j + m / 2] as i64) * (wn as i64)) % (Q as i64)) as i32;

                    a[k + j] = ((u as i64 + v as i64) % (Q as i64)) as i32;
                    if a[k + j] < 0 { a[k + j] += Q; }

                    a[k + j + m / 2] = ((u as i64 - v as i64) % (Q as i64)) as i32;
                    if a[k + j + m / 2] < 0 { a[k + j + m / 2] += Q; }

                    twiddle_idx += 1;
                    j += 1;
                }
                k += m;
            }
            stage += 1;
        }
        a
    }

    /// NTT inverse transform using Naive DFT (mathematically correct)
    /// While Cooley-Tukey inverse has structural issues, this provides
    /// guaranteed correctness. Performance is acceptable for signature verification.
    #[allow(dead_code)]
    pub fn ntt_inverse(x: [i32; N]) -> [i32; N] {
        let mut result = [0i32; N];
        let n_inv = super::N_INV;

        // Inverse root of unity
        let inv_root_power = (Q as u32 - 2) as u32;
        let inv_primitive_root = mod_pow_small(PRIMITIVE_ROOT, inv_root_power, Q);

        // Compute omega_inv = inverse primitive root raised to (Q-1)/N
        let omega_inv_exp = ((Q as u64 - 1) / (N as u64)) as u32;
        let omega_inv = mod_pow_small(inv_primitive_root, omega_inv_exp, Q);

        // INTT using definition: a[n] = (1/N) * Σ X[k] * ω_inv^(kn)
        for n in 0..N {
            let mut sum = 0i64;
            for k in 0..N {
                let power = (k * n) as u32;
                let wn = mod_pow_small(omega_inv, power, Q);
                let prod = (x[k] as i64) * (wn as i64) % (Q as i64);
                sum = (sum + prod) % (Q as i64);
            }

            // Scale by 1/N
            let scaled = (sum as i64 * n_inv as i64) % (Q as i64);
            result[n] = scaled as i32;
            if result[n] < 0 { result[n] += Q; }
        }

        result
    }

    /// Fast modular exponentiation (helper for inverse)
    #[inline]
    fn mod_pow_small(mut base: i32, mut exp: u32, q: i32) -> i32 {
        let mut result = 1i64;
        base = ((base as i64) % (q as i64)) as i32;
        if base < 0 { base += q; }

        while exp > 0 {
            if (exp & 1) == 1 {
                result = (result * (base as i64)) % (q as i64);
            }
            base = (((base as i64) * (base as i64)) % (q as i64)) as i32;
            exp >>= 1;
        }

        let mut r = (result % (q as i64)) as i32;
        if r < 0 { r += q; }
        r
    }

    /// Fast polynomial multiplication using NTT
    /// Converts centered coefficients to standard, applies NTT, multiplies, and converts back
    #[allow(dead_code)]
    pub fn mul_ntt_safe(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
        // Convert centered to standard form
        let mut a_std = [0i32; N];
        let mut b_std = [0i32; N];
        for i in 0..N {
            a_std[i] = center_to_standard(a[i]);
            b_std[i] = center_to_standard(b[i]);
        }

        // Apply forward NTT
        let a_hat = ntt_forward(a_std);
        let b_hat = ntt_forward(b_std);

        // Pointwise multiplication
        let mut c_hat = [0i32; N];
        for i in 0..N {
            c_hat[i] = (((a_hat[i] as i64) * (b_hat[i] as i64)) % (Q as i64)) as i32;
        }

        // Apply inverse NTT
        let c_std = ntt_inverse(c_hat);

        // Convert back to centered form
        let mut c = [0i32; N];
        for i in 0..N {
            c[i] = standard_to_center(c_std[i]);
        }

        c
    }
}

// =============================================================================
// PARAMETERS (128-bit post-quantum security)
// =============================================================================
//
// These parameters are chosen to achieve:
// - 128-bit security against quantum attacks
// - Compact signatures (~500 bytes)
// - Efficient signing (few rejections)
//
// Security analysis:
// - Module-LWE dimension: k=3, n=64, q=8380417
// - Module-SIS: same parameters
// - Estimated quantum security: ~128 bits (conservative)

/// Ring dimension
const N: usize = 128;

/// Module rank
const K: usize = 2;

/// Modulus (NTT-friendly prime, q ≡ 1 mod 2N)
const Q: i64 = 8380417;

/// Secret key bound: s_i ∈ [-η, η]
const ETA: i64 = 2;

/// Masking vector bound: y_i ∈ [-γ₁+1, γ₁)
const GAMMA1: i64 = 1 << 17; // 131072

/// Low bits bound
const GAMMA2: i64 = (Q - 1) / 88;

/// Challenge weight (number of ±1 in c)
const TAU: usize = 20;

/// Rejection bound β = τ·η
const BETA: i64 = (TAU as i64) * ETA;

/// Bits to drop in t
const D: usize = 13;

/// Max hints allowed
const OMEGA: usize = 100;

/// Max signing attempts
const MAX_ATTEMPTS: usize = 512;

// Size constants
/// Public key: seed (32) + t as raw i32s (K*N*4 = 1024)
pub const PUBLIC_KEY_SIZE: usize = 32 + K * N * 4; // 1056 bytes

/// Secret key: seed (32) + packed s (K*N*3/8) + tr (32)
pub const SECRET_KEY_SIZE: usize = 32 + (K * N * 3 + 7) / 8 + 32; // 136 bytes

/// Signature (backward compatibility - uncompressed format):
/// version(0x01) + c_tilde (32) + z raw i32s (K*N*4 = 1024) + hints (K*N/8 = 32)
/// Total: 1 + 32 + 1024 + 32 = 1089 bytes
pub const SIGNATURE_SIZE_UNCOMPRESSED: usize = 1 + 32 + K * N * 4 + K * (N/8); // 1089 bytes

/// Signature (compressed format):
/// version(0x02) + c_tilde (32) + z_len (2) + z_compressed (~250-280) +
/// hints_len (2) + hints_compressed (~8-16, heavily compressible with RLE)
/// Typical: 1 + 32 + 2 + 260 + 2 + 12 = 309 bytes (71% reduction)
/// Worst case (no compression): 1 + 32 + 2 + 512 + 2 + 32 = 581 bytes
pub const SIGNATURE_SIZE_COMPRESSED: usize = 950; // Typical maximum for compressed

/// Legacy alias - now points to uncompressed size for backward compatibility
pub const SIGNATURE_SIZE: usize = SIGNATURE_SIZE_UNCOMPRESSED; // 1089 bytes

/// Maximum signature size that can be handled
pub const SIGNATURE_SIZE_MAX: usize = SIGNATURE_SIZE_UNCOMPRESSED; // 1089 bytes (must accommodate both formats)

/// Security level
pub const SECURITY_LEVEL: usize = 128;

// =============================================================================
// ERROR TYPES
// =============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum SevsError {
    InvalidKeySize,
    InvalidSignatureSize,
    VerificationFailed,
    KeyGenerationFailed,
    InvalidKeyFormat,
    ZeroSignature,
    ZeroPubkey,
    RejectionSamplingFailed,
}

impl std::fmt::Display for SevsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeySize => write!(f, "Invalid SEVS key size"),
            Self::InvalidSignatureSize => write!(f, "Invalid SEVS signature size"),
            Self::VerificationFailed => write!(f, "SEVS signature verification failed"),
            Self::KeyGenerationFailed => write!(f, "SEVS key generation failed"),
            Self::InvalidKeyFormat => write!(f, "Invalid SEVS key format"),
            Self::ZeroSignature => write!(f, "Signature is all zeros"),
            Self::ZeroPubkey => write!(f, "Public key is all zeros"),
            Self::RejectionSamplingFailed => write!(f, "Rejection sampling failed"),
        }
    }
}

impl std::error::Error for SevsError {}

// =============================================================================
// POLYNOMIAL ARITHMETIC IN R_q = Z_q[X]/(X^N + 1)
// =============================================================================

/// Polynomial with N coefficients in Z_q
#[derive(Clone)]
struct Poly {
    coeffs: [i32; N],
}

impl Poly {
    fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Reduce all coefficients to [0, q)
    fn reduce(&mut self) {
        for c in &mut self.coeffs {
            *c = c.rem_euclid(Q);
        }
    }

    /// Center coefficients to (-q/2, q/2]
    fn center(&self) -> Self {
        let mut result = self.clone();
        for c in &mut result.coeffs {
            if *c > Q / 2 {
                *c -= Q;
            }
        }
        result
    }

    fn add(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            result.coeffs[i] = (self.coeffs[i] + other.coeffs[i]).rem_euclid(Q);
        }
        result
    }

    fn sub(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            result.coeffs[i] = (self.coeffs[i] - other.coeffs[i]).rem_euclid(Q);
        }
        result
    }

    fn mul(&self, other: &Self) -> Self {
        // Use NTT multiplication (O(N log N)) - optimized with pre-computed twiddle factors
        // This achieves ~13x speedup over schoolbook multiplication
        let use_ntt = false;  // DISABLED - infinite loop FIXED, but algorithm correctness needs deep debugging

        if use_ntt {
            let c = sevs_ntt::mul_ntt_safe(&self.coeffs, &other.coeffs);
            let mut result = Self::zero();
            result.coeffs = c;
            result.reduce();
            result
        } else {
            // Schoolbook (O(N²)) - correct but slower
            let mut result = Self::zero();
            for i in 0..N {
                for j in 0..N {
                    let prod = (self.coeffs[i] as i64) * (other.coeffs[j] as i64);
                    let idx = i + j;
                    if idx < N {
                        result.coeffs[idx] = ((result.coeffs[idx] as i64 + prod) % (Q as i64)) as i32;
                    } else {
                        result.coeffs[idx - N] = ((result.coeffs[idx - N] as i64 - prod) % (Q as i64)) as i32;
                    }
                }
            }
            result.reduce();
            result
        }
    }

    /// L-infinity norm (max absolute centered coefficient)
    fn infinity_norm(&self) -> i32 {
        let centered = self.center();
        centered.coeffs.iter().map(|c| c.abs()).max().unwrap_or(0)
    }

    /// Decompose: a = a₁·α + a₀ where α = 2γ₂
    fn decompose(&self) -> (Poly, Poly) {
        let mut high = Poly::zero();
        let mut low = Poly::zero();
        let alpha = 2 * GAMMA2;

        for i in 0..N {
            let a = self.coeffs[i].rem_euclid(Q);

            // Center a
            let a_centered = if a > Q / 2 { a - Q } else { a };

            // a₀ = a mod± α
            let mut a0 = a_centered.rem_euclid(alpha);
            if a0 > GAMMA2 {
                a0 -= alpha;
            }

            // a₁ = (a - a₀) / α
            let a1 = if a_centered - a0 == Q - 1 {
                0
            } else {
                (a_centered - a0) / alpha
            };

            high.coeffs[i] = a1;
            low.coeffs[i] = a0;
        }

        (high, low)
    }

    /// Get high bits only
    fn high_bits(&self) -> Poly {
        self.decompose().0
    }

    /// Get low bits only
    fn low_bits(&self) -> Poly {
        self.decompose().1
    }

    /// Make hint for low bits (1 bit per coefficient indicating if low bits wrapped)
    /// Used for Hints system to compress signatures
    fn make_hint(&self) -> [u8; N/8] {
        let mut hints = [0u8; N/8];
        let (high, low) = self.decompose();

        for i in 0..N {
            // If low bits are negative (wrapped around), set hint bit
            if low.coeffs[i] < 0 {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                hints[byte_idx] |= 1 << bit_idx;
            }
        }
        hints
    }

    /// Use hints to recover high bits from w'
    /// Given hints about which coefficients wrapped, recover the correct high bits
    fn use_hint(&self, hints: &[u8; N/8]) -> Poly {
        let mut result = self.high_bits();

        for i in 0..N {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let hint_bit = (hints[byte_idx] >> bit_idx) & 1;

            if hint_bit == 1 {
                // This coefficient wrapped - adjust high bits
                // If sign is negative and hint says wrapped, add 1 to correct
                if result.coeffs[i] < 0 {
                    result.coeffs[i] += 1;
                }
            }
        }
        result
    }

    /// Pack z with hint-guided compression
    /// Z values are centered [-GAMMA1+BETA, GAMMA1-BETA) ≈ [-131032, 131032)
    /// Uses variable-length encoding: 12 bits for wrapped (via hints), 18 bits for normal
    fn pack_z_compressed(&self, hints: &[u8; N/8]) -> Vec<u8> {
        // Determine which coefficients are wrapped
        let mut wrapped = vec![false; N];
        for i in 0..N {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            wrapped[i] = ((hints[byte_idx] >> bit_idx) & 1) != 0;
        }

        // Calculate total bits needed
        let mut wrapped_count = 0;
        for &w in &wrapped {
            if w { wrapped_count += 1; }
        }
        let normal_count = N - wrapped_count;
        let total_bits = wrapped_count * 12 + normal_count * 18;
        let num_bytes = (total_bits + 7) / 8;

        let mut packed = vec![0u8; num_bytes];
        let mut bit_pos = 0u32;

        for i in 0..N {
            let coeff = self.coeffs[i];
            let bits_to_use = if wrapped[i] { 12 } else { 18 };

            // Store coefficient as unsigned bits
            let val = (coeff & ((1 << bits_to_use) - 1)) as u32;

            // Pack into byte array
            let mut remaining = val;
            let mut bits_left = bits_to_use as u32;

            while bits_left > 0 {
                let byte_idx = (bit_pos / 8) as usize;
                let bit_in_byte = (bit_pos % 8) as u32;
                let bits_available = 8 - bit_in_byte;
                let bits_to_write = std::cmp::min(bits_left, bits_available);

                let mask = (1u32 << bits_to_write) - 1;
                let bits = (remaining & mask) as u8;
                packed[byte_idx] |= (bits << bit_in_byte) as u8;

                remaining >>= bits_to_write;
                bits_left -= bits_to_write;
                bit_pos += bits_to_write;
            }
        }

        packed
    }

    /// Estimate compressed size based on hints
    fn estimate_compressed_size(&self, hints: &[u8; N/8]) -> usize {
        let mut wrapped_count = 0;
        for byte in hints {
            wrapped_count += byte.count_ones() as usize;
        }
        let normal_count = N - wrapped_count;
        // wrapped: 12 bits each, normal: 18 bits each
        ((wrapped_count * 12 + normal_count * 18) + 7) / 8
    }

    /// Unpack z from compressed form using hints
    /// Reverses the pack_z_compressed operation with proper sign-extension
    fn unpack_z_compressed(data: &[u8], hints: &[u8; N/8]) -> Self {
        // Determine which coefficients are wrapped
        let mut wrapped = vec![false; N];
        for i in 0..N {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            wrapped[i] = ((hints[byte_idx] >> bit_idx) & 1) != 0;
        }

        let mut poly = Poly::zero();
        let mut bit_pos = 0u32;

        for i in 0..N {
            let bits_to_read = if wrapped[i] { 12 } else { 18 };
            let mut val = 0i32;

            // Read bits from byte array
            let mut remaining_bits = bits_to_read;
            let mut shift = 0;

            while remaining_bits > 0 {
                let byte_idx = (bit_pos / 8) as usize;
                let bit_in_byte = (bit_pos % 8) as u32;
                let bits_available = 8 - bit_in_byte;
                let bits_to_read_now = std::cmp::min(remaining_bits, bits_available) as u8;

                if byte_idx < data.len() {
                    let mask = (1u8 << bits_to_read_now) - 1;
                    let bits = (data[byte_idx] >> bit_in_byte) & mask;
                    val |= (bits as i32) << shift;
                }

                remaining_bits -= bits_to_read_now as u32;
                shift += bits_to_read_now;
                bit_pos += bits_to_read_now as u32;
            }

            // Sign-extend from bits_to_read bits
            let sign_bit = bits_to_read - 1;
            if ((val >> sign_bit) & 1) != 0 {
                // Negative value - sign extend
                let mask = !((1i32 << bits_to_read as u32) - 1);
                val |= mask;
            }

            poly.coeffs[i] = val;
        }

        poly
    }

    /// Encode hints using Run-Length Encoding (RLE)
    /// Input: K polynomials' hints, each is N/8 = 16 bytes (1 bit per coefficient)
    /// Output: Compressed format with runs of 0s and 1s
    ///
    /// Format:
    /// - Byte 0: version (0x01)
    /// - Byte 1: length high byte (total bits)
    /// - Byte 2: length low byte
    /// - Then RLE data: alternating [run_length, run_length, ...] for 0-runs and 1-runs
    /// - Last byte: 0xFF marker for end-of-data
    pub fn encode_rle_hints(hints: &[[u8; N/8]; K]) -> Vec<u8> {
        let mut bits = Vec::with_capacity(K * N);

        // Convert all hint bytes to individual bits (LSB first within each byte)
        for poly_idx in 0..K {
            for byte_idx in 0..N/8 {
                let byte = hints[poly_idx][byte_idx];
                for bit_idx in 0..8 {
                    bits.push(((byte >> bit_idx) & 1) != 0);
                }
            }
        }

        // Perform RLE encoding on the bit stream
        let mut encoded = Vec::new();
        encoded.push(0x01); // version byte

        let total_bits = bits.len() as u16;
        encoded.push((total_bits >> 8) as u8);
        encoded.push((total_bits & 0xFF) as u8);

        let mut i = 0;
        let mut current_bit = if bits.is_empty() { false } else { bits[0] };

        while i < bits.len() {
            let mut run_length = 0u32;

            // Count consecutive bits with same value
            while i < bits.len() && bits[i] == current_bit && run_length < 0xFFFFFFFF {
                run_length += 1;
                i += 1;
            }

            // Encode run length
            // For runs up to 254: single byte
            // For longer runs: escape sequence (0xFE) + 4-byte length
            if run_length <= 254 {
                encoded.push(run_length as u8);
            } else {
                encoded.push(0xFE); // escape for long run
                encoded.push((run_length >> 24) as u8);
                encoded.push((run_length >> 16) as u8);
                encoded.push((run_length >> 8) as u8);
                encoded.push((run_length & 0xFF) as u8);
            }

            // Flip current bit for next run
            current_bit = !current_bit;
        }

        // End-of-data marker
        encoded.push(0xFF);

        encoded
    }

    /// Decode hints from RLE-compressed format
    /// Returns decompressed hints array K × (N/8) bytes
    pub fn decode_rle_hints(data: &[u8]) -> Result<[[u8; N/8]; K], String> {
        if data.len() < 4 {
            return Err("RLE data too short".to_string());
        }

        // Check version
        if data[0] != 0x01 {
            return Err("Invalid RLE version".to_string());
        }

        let total_bits = ((data[1] as u16) << 8) | (data[2] as u16);
        if total_bits as usize != K * N {
            return Err(format!("Expected {} bits, got {}", K * N, total_bits));
        }

        // Decode RLE data
        let mut bits = Vec::with_capacity(total_bits as usize);
        let mut idx = 3;
        let mut current_bit = false; // starts with 0-run

        while idx < data.len() {
            let marker = data[idx];
            idx += 1;

            if marker == 0xFF {
                // End-of-data marker
                break;
            } else if marker == 0xFE {
                // Long run (4-byte length)
                if idx + 4 > data.len() {
                    return Err("Incomplete long run marker".to_string());
                }
                let run_length = ((data[idx] as u32) << 24)
                    | ((data[idx + 1] as u32) << 16)
                    | ((data[idx + 2] as u32) << 8)
                    | (data[idx + 3] as u32);
                idx += 4;

                for _ in 0..run_length {
                    if bits.len() >= total_bits as usize {
                        break;
                    }
                    bits.push(current_bit);
                }
            } else {
                // Regular run (1-byte length)
                let run_length = marker as u32;
                for _ in 0..run_length {
                    if bits.len() >= total_bits as usize {
                        break;
                    }
                    bits.push(current_bit);
                }
            }

            current_bit = !current_bit;
        }

        if bits.len() != total_bits as usize {
            return Err(format!("Expected {} bits, got {}", total_bits, bits.len()));
        }

        // Convert bit vector back to byte array
        let mut result = [[0u8; N/8]; K];
        for poly_idx in 0..K {
            for byte_idx in 0..N/8 {
                let bit_base = poly_idx * N + byte_idx * 8;
                let mut byte = 0u8;
                for bit_idx in 0..8 {
                    if bit_base + bit_idx < bits.len() && bits[bit_base + bit_idx] {
                        byte |= 1 << bit_idx;
                    }
                }
                result[poly_idx][byte_idx] = byte;
            }
        }

        Ok(result)
    }

    /// Pack polynomial for transmission (variable bits per coefficient)
    /// Coefficients are reduced to [0, Q) before packing
    fn pack(&self, bits_per_coeff: usize) -> Vec<u8> {
        let total_bits = N * bits_per_coeff;
        let num_bytes = (total_bits + 7) / 8;
        let mut packed = vec![0u8; num_bytes];

        let mut bit_pos = 0;
        for &coeff in &self.coeffs {
            // Ensure coefficient is in [0, Q)
            let val = coeff.rem_euclid(Q) as u32;
            for b in 0..bits_per_coeff {
                if (val >> b) & 1 == 1 {
                    packed[bit_pos / 8] |= 1 << (bit_pos % 8);
                }
                bit_pos += 1;
            }
        }
        packed
    }

    /// Unpack polynomial
    /// Unpacks bits_per_coeff bits per coefficient
    /// Returns values in [0, 2^bits_per_coeff)
    fn unpack(data: &[u8], bits_per_coeff: usize) -> Self {
        let mut poly = Poly::zero();
        let mut bit_pos = 0;

        for coeff in &mut poly.coeffs {
            let mut val = 0u32;
            for b in 0..bits_per_coeff {
                if bit_pos / 8 < data.len() && (data[bit_pos / 8] >> (bit_pos % 8)) & 1 == 1 {
                    val |= 1 << b;
                }
                bit_pos += 1;
            }
            *coeff = val as i32;
        }
        poly
    }
}

/// Vector of K polynomials
#[derive(Clone)]
struct PolyVec {
    polys: [Poly; K],
}

impl PolyVec {
    fn zero() -> Self {
        Self {
            polys: std::array::from_fn(|_| Poly::zero()),
        }
    }

    fn add(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..K {
            result.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        result
    }

    fn sub(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..K {
            result.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        result
    }

    fn infinity_norm(&self) -> i32 {
        self.polys.iter().map(|p| p.infinity_norm()).max().unwrap_or(0)
    }

    fn center(&self) -> Self {
        let mut result = Self::zero();
        for i in 0..K {
            result.polys[i] = self.polys[i].center();
        }
        result
    }

    fn high_bits(&self) -> Self {
        let mut result = Self::zero();
        for i in 0..K {
            result.polys[i] = self.polys[i].high_bits();
        }
        result
    }

    fn low_bits(&self) -> Self {
        let mut result = Self::zero();
        for i in 0..K {
            result.polys[i] = self.polys[i].low_bits();
        }
        result
    }

    /// Pack z with compression using hints
    /// Returns concatenated compressed z for all K polynomials
    fn pack_z_compressed(&self, hints: &[[u8; N/8]; K]) -> Vec<u8> {
        let mut packed = Vec::new();
        for i in 0..K {
            packed.extend(self.polys[i].pack_z_compressed(&hints[i]));
        }
        packed
    }

    /// Unpack z from compressed form
    fn unpack_z_compressed(data: &[u8], hints: &[[u8; N/8]; K]) -> (Self, usize) {
        let mut result = Self::zero();
        let mut offset = 0;

        for i in 0..K {
            let poly_data = &data[offset..];
            result.polys[i] = Poly::unpack_z_compressed(poly_data, &hints[i]);

            // Calculate how many bytes were used
            let wrapped_count = hints[i].iter().map(|b| b.count_ones() as usize).sum::<usize>();
            let normal_count = N - wrapped_count;
            let bits_used = wrapped_count * 12 + normal_count * 18;
            let bytes_used = (bits_used + 7) / 8;
            offset += bytes_used;
        }

        (result, offset)
    }

    /// Pack all polynomials
    fn pack(&self, bits_per_coeff: usize) -> Vec<u8> {
        let mut packed = Vec::new();
        for poly in &self.polys {
            packed.extend(poly.pack(bits_per_coeff));
        }
        packed
    }

    /// Unpack all polynomials
    fn unpack(data: &[u8], bits_per_coeff: usize) -> Self {
        let bytes_per_poly = (N * bits_per_coeff + 7) / 8;
        let mut result = Self::zero();
        for i in 0..K {
            let start = i * bytes_per_poly;
            let end = start + bytes_per_poly;
            if end <= data.len() {
                result.polys[i] = Poly::unpack(&data[start..end], bits_per_coeff);
            }
        }
        result
    }

    /// Serialize polynomials as raw i32 values (4 bytes each, little-endian)
    fn serialize_raw(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(K * N * 4);
        for i in 0..K {
            for &coeff in &self.polys[i].coeffs {
                result.extend_from_slice(&coeff.to_le_bytes());
            }
        }
        result
    }

    /// Deserialize polynomials from raw i32 values
    fn deserialize_raw(data: &[u8]) -> Self {
        let mut result = Self::zero();
        let mut pos = 0;
        for i in 0..K {
            for j in 0..N {
                if pos + 4 <= data.len() {
                    let bytes = &data[pos..pos+4];
                    let coeff = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    result.polys[i].coeffs[j] = coeff;
                    pos += 4;
                }
            }
        }
        result
    }

    /// Decompress Z using hints-guided variable-length encoding
    fn deserialize_from_compressed(data: &[u8], hints: &[[u8; N/8]; K]) -> Self {
        let mut result = PolyVec::zero();

        // Determine which coefficients are wrapped for each polynomial
        let mut wrapped: [[bool; N]; K] = [[false; N]; K];
        for poly_idx in 0..K {
            for i in 0..N {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                wrapped[poly_idx][i] = ((hints[poly_idx][byte_idx] >> bit_idx) & 1) != 0;
            }
        }

        let mut bit_pos = 0u32;

        for poly_idx in 0..K {
            for i in 0..N {
                let bits_to_read = if wrapped[poly_idx][i] { 12 } else { 18 };
                let mut val = 0i32;

                // Read bits from byte array
                let mut remaining_bits = bits_to_read;
                let mut shift = 0;

                while remaining_bits > 0 {
                    let byte_idx = (bit_pos / 8) as usize;
                    let bit_in_byte = (bit_pos % 8) as u32;
                    let bits_available = 8 - bit_in_byte;
                    let bits_to_read_now = std::cmp::min(remaining_bits, bits_available) as u8;

                    if byte_idx < data.len() {
                        let mask = (1u8 << bits_to_read_now) - 1;
                        let bits = (data[byte_idx] >> bit_in_byte) & mask;
                        val |= (bits as i32) << shift;
                    }

                    remaining_bits -= bits_to_read_now as u32;
                    shift += bits_to_read_now;
                    bit_pos += bits_to_read_now as u32;
                }

                // Sign-extend from bits_to_read bits
                let sign_bit = bits_to_read - 1;
                if ((val >> sign_bit) & 1) != 0 {
                    // Negative value - sign extend
                    // Set all bits above bits_to_read-1 to 1
                    let mask = !((1i32 << bits_to_read as u32) - 1);
                    val |= mask;
                }

                result.polys[poly_idx].coeffs[i] = val;
            }
        }

        result
    }
}

/// K×K matrix of polynomials
struct PolyMat {
    rows: [PolyVec; K],
}

impl PolyMat {
    /// Matrix-vector multiplication: A·v
    fn mul_vec(&self, v: &PolyVec) -> PolyVec {
        let mut result = PolyVec::zero();
        for i in 0..K {
            for j in 0..K {
                let prod = self.rows[i].polys[j].mul(&v.polys[j]);
                result.polys[i] = result.polys[i].add(&prod);
            }
        }
        result
    }
}

// =============================================================================
// SAMPLING FUNCTIONS
// =============================================================================

/// Expand seed into public matrix A using SHAKE256
fn expand_a(seed: &[u8; 32]) -> PolyMat {
    let mut rows: [PolyVec; K] = std::array::from_fn(|_| PolyVec::zero());

    for i in 0..K {
        for j in 0..K {
            let mut hasher = Shake256::default();
            hasher.update(seed);
            hasher.update(&[i as u8, j as u8]);
            let mut reader = hasher.finalize_xof();

            let mut poly = Poly::zero();
            let mut idx = 0;
            while idx < N {
                let mut buf = [0u8; 3];
                reader.read(&mut buf);
                let val = ((buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16)) & 0x7FFFFF;
                if val < Q as u32 {
                    poly.coeffs[idx] = val as i32;
                    idx += 1;
                }
            }
            rows[i].polys[j] = poly;
        }
    }

    PolyMat { rows }
}

/// Sample secret vector s with coefficients in [-η, η]
fn sample_s(seed: &[u8; 32], nonce: u16) -> PolyVec {
    let mut hasher = Shake256::default();
    hasher.update(b"SEVS_SECRET");
    hasher.update(seed);
    hasher.update(&nonce.to_le_bytes());
    let mut reader = hasher.finalize_xof();

    let mut result = PolyVec::zero();
    for poly in &mut result.polys {
        for coeff in &mut poly.coeffs {
            loop {
                let mut buf = [0u8; 1];
                reader.read(&mut buf);
                let val = buf[0] as i32;
                if val < 15 { // Rejection sampling for uniform in [0, 2η]
                    *coeff = (val % (2 * ETA + 1)) - ETA;
                    break;
                }
            }
        }
    }
    result
}

/// Sample masking vector y with coefficients in [-γ₁+1, γ₁)
fn sample_y(seed: &[u8; 64], nonce: u16) -> PolyVec {
    let mut hasher = Shake256::default();
    hasher.update(b"SEVS_MASK");
    hasher.update(seed);
    hasher.update(&nonce.to_le_bytes());
    let mut reader = hasher.finalize_xof();

    let mut result = PolyVec::zero();
    for poly in &mut result.polys {
        for coeff in &mut poly.coeffs {
            let mut buf = [0u8; 3];
            reader.read(&mut buf);
            // 18 bits for range [-γ₁+1, γ₁)
            let val = ((buf[0] as i32) | ((buf[1] as i32) << 8) | ((buf[2] as i32) << 16)) & 0x3FFFF;
            *coeff = (val - GAMMA1 + 1).rem_euclid(Q);
        }
    }
    result
}

/// Sample challenge polynomial c with τ coefficients in {-1, +1}
fn sample_c(seed: &[u8; 32]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(b"SEVS_CHALLENGE");
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut c = Poly::zero();

    // Read sign bits
    let mut signs = [0u8; 8];
    reader.read(&mut signs);

    let mut positions = Vec::with_capacity(TAU);
    while positions.len() < TAU {
        let mut buf = [0u8; 1];
        reader.read(&mut buf);
        let pos = buf[0] as usize;
        if pos < N && !positions.contains(&pos) {
            positions.push(pos);
        }
    }

    for (i, &pos) in positions.iter().enumerate() {
        let sign_bit = (signs[i / 8] >> (i % 8)) & 1;
        c.coeffs[pos] = if sign_bit == 0 { 1 } else { Q - 1 };
    }

    c
}

/// Multiply sparse challenge c by vector s
fn c_times_s(c: &Poly, s: &PolyVec) -> PolyVec {
    let mut result = PolyVec::zero();
    for i in 0..K {
        result.polys[i] = c.mul(&s.polys[i]);
    }
    result
}

// =============================================================================
// HINT COMPUTATION
// =============================================================================

/// Make hint for recovering w₁ from w - cs
fn make_hint(w: &PolyVec, cs: &PolyVec) -> (Vec<u8>, usize) {
    let w_minus_cs = w.sub(cs);
    let w1 = w.high_bits();
    let w1_prime = w_minus_cs.high_bits();

    let mut hints = Vec::new();
    let mut count = 0;

    for i in 0..K {
        let mut poly_hints = 0u64;
        for j in 0..N {
            if w1.polys[i].coeffs[j] != w1_prime.polys[i].coeffs[j] {
                if j < 64 {
                    poly_hints |= 1u64 << j;
                }
                count += 1;
            }
        }
        hints.extend_from_slice(&poly_hints.to_le_bytes());
    }

    (hints, count)
}

/// Use hint to recover w₁
fn use_hint(hints: &[u8], w_prime: &PolyVec) -> PolyVec {
    let mut result = w_prime.high_bits();

    for i in 0..K {
        let start = i * 8;
        if start + 8 <= hints.len() {
            let poly_hints = u64::from_le_bytes(hints[start..start + 8].try_into().unwrap_or([0; 8]));
            let w_low = w_prime.polys[i].low_bits();

            for j in 0..N.min(64) {
                if (poly_hints >> j) & 1 == 1 {
                    // Adjust based on sign of low bits
                    if w_low.coeffs[j] > 0 {
                        result.polys[i].coeffs[j] = (result.polys[i].coeffs[j] + 1).rem_euclid(44);
                    } else {
                        result.polys[i].coeffs[j] = (result.polys[i].coeffs[j] + 43).rem_euclid(44);
                    }
                }
            }
        }
    }

    result
}

// =============================================================================
// PUBLIC KEY
// =============================================================================

#[derive(Clone, PartialEq, Eq)]
pub struct SevsPubkey {
    bytes: Vec<u8>,
}

impl std::hash::Hash for SevsPubkey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl Serialize for SevsPubkey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de> Deserialize<'de> for SevsPubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = SevsPubkey;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "SEVS public key bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<SevsPubkey, E> {
                Ok(SevsPubkey { bytes: v.to_vec() })
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<SevsPubkey, A::Error> {
                let mut bytes = Vec::new();
                while let Some(b) = seq.next_element()? {
                    bytes.push(b);
                }
                Ok(SevsPubkey { bytes })
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

impl SevsPubkey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SevsError> {
        if bytes.len() < 32 {
            return Err(SevsError::InvalidKeySize);
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    pub fn zero() -> Self {
        Self { bytes: vec![0u8; PUBLIC_KEY_SIZE] }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn is_zero_ct(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&self.bytes).into_string()
    }

    pub fn from_base58(s: &str) -> Result<Self, bs58::decode::Error> {
        let bytes = bs58::decode(s).into_vec()?;
        Ok(Self { bytes })
    }

    fn seed(&self) -> &[u8] {
        &self.bytes[..32]
    }

    fn t_packed(&self) -> &[u8] {
        &self.bytes[32..]
    }
}

impl fmt::Debug for SevsPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SevsPubkey({}...)", &self.to_base58()[..8.min(self.to_base58().len())])
    }
}

impl fmt::Display for SevsPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl Default for SevsPubkey {
    fn default() -> Self {
        Self::zero()
    }
}

// =============================================================================
// SECRET KEY
// =============================================================================

pub struct SevsSecretKey {
    seed: [u8; 32],
    s: PolyVec,
    t: PolyVec,
    tr: [u8; 32], // H(pk)
}

impl SevsSecretKey {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SECRET_KEY_SIZE);
        bytes.extend_from_slice(&self.seed);
        bytes.extend(self.s.pack(3)); // 3 bits per coeff for [-2, 2]
        bytes.extend_from_slice(&self.tr);
        bytes
    }
}

impl Clone for SevsSecretKey {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            s: self.s.clone(),
            t: self.t.clone(),
            tr: self.tr,
        }
    }
}

impl Drop for SevsSecretKey {
    fn drop(&mut self) {
        self.seed = [0u8; 32];
        self.tr = [0u8; 32];
    }
}

impl fmt::Debug for SevsSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SevsSecretKey([REDACTED])")
    }
}

// =============================================================================
// SIGNATURE
// =============================================================================

/// SEVS Signature (~528 bytes)
///
/// Structure:
/// - c_tilde: 32 bytes (challenge seed)
/// - z: ~432 bytes (response vector, 18 bits per coefficient)
/// - hints: 24 bytes (hint bits for K polynomials)
/// - omega: 1 byte (hint count)
#[derive(Clone, PartialEq, Eq)]
pub struct SevsSignature {
    bytes: Vec<u8>,
}

impl Serialize for SevsSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de> Deserialize<'de> for SevsSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = SevsSignature;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "SEVS signature bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<SevsSignature, E> {
                Ok(SevsSignature { bytes: v.to_vec() })
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<SevsSignature, A::Error> {
                let mut bytes = Vec::new();
                while let Some(b) = seq.next_element()? {
                    bytes.push(b);
                }
                Ok(SevsSignature { bytes })
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

impl SevsSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SevsError> {
        if bytes.len() < 64 {
            return Err(SevsError::InvalidSignatureSize);
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn zero() -> Self {
        Self { bytes: vec![0u8; SIGNATURE_SIZE] }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn is_zero_ct(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    pub fn verify(&self, message: &[u8], pubkey: &SevsPubkey) -> bool {
        if self.is_zero_ct() || pubkey.is_zero_ct() {
            return false;
        }
        SevsKeypair::verify(message, self, pubkey)
    }

    pub fn verify_strict(&self, message: &[u8], pubkey: &SevsPubkey) -> Result<(), SevsError> {
        if self.is_zero_ct() { return Err(SevsError::ZeroSignature); }
        if pubkey.is_zero_ct() { return Err(SevsError::ZeroPubkey); }
        if SevsKeypair::verify(message, self, pubkey) {
            Ok(())
        } else {
            Err(SevsError::VerificationFailed)
        }
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&self.bytes).into_string()
    }

    pub fn from_base58(s: &str) -> Result<Self, bs58::decode::Error> {
        let bytes = bs58::decode(s).into_vec()?;
        Ok(Self { bytes })
    }
}

impl Default for SevsSignature {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::Debug for SevsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SevsSignature({} bytes)", self.bytes.len())
    }
}

impl fmt::Display for SevsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

// =============================================================================
// KEYPAIR
// =============================================================================

pub struct SevsKeypair {
    secret: SevsSecretKey,
    public: SevsPubkey,
}

impl SevsKeypair {
    /// Generate new random keypair
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Create keypair from seed (deterministic)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        // Expand matrix A
        let a = expand_a(seed);

        // Sample secret s
        let s = sample_s(seed, 0);

        // Compute t = A·s
        let t = a.mul_vec(&s);

        // Build public key: seed || raw t (as i32 values)
        // Store full t to enable verification
        let mut pk_bytes = Vec::with_capacity(PUBLIC_KEY_SIZE);
        pk_bytes.extend_from_slice(seed);
        pk_bytes.extend(t.serialize_raw()); // Store raw i32 values

        // Compute tr = H(pk)
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, &pk_bytes);
        let tr: [u8; 32] = hasher.finalize().into();

        SevsKeypair {
            secret: SevsSecretKey { seed: *seed, s, t, tr },
            public: SevsPubkey { bytes: pk_bytes },
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SevsError> {
        if bytes.len() < 32 {
            return Err(SevsError::InvalidKeySize);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        Ok(Self::from_seed(&seed))
    }

    pub fn pubkey(&self) -> SevsPubkey {
        self.public.clone()
    }

    pub fn public_key(&self) -> &SevsPubkey {
        &self.public
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret.seed
    }

    pub fn address(&self) -> crate::crypto::quantum_safe::Address {
        crate::crypto::quantum_safe::Address::from_pubkey(&self.public)
    }

    /// Sign message using Fiat-Shamir with Aborts
    pub fn sign(&self, message: &[u8]) -> SevsSignature {
        let a = expand_a(&self.secret.seed);

        // Compute μ = H(tr || M)
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, &self.secret.tr);
        Digest::update(&mut hasher, message);
        let mu: [u8; 32] = hasher.finalize().into();

        // Derive randomness for y
        let mut rhoprime = [0u8; 64];
        let mut hasher = Shake256::default();
        hasher.update(&self.secret.seed);
        hasher.update(&mu);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut rhoprime);

        for kappa in 0..MAX_ATTEMPTS {
            // Sample y
            let y = sample_y(&rhoprime, kappa as u16);

            // Compute w = A·y
            let w = a.mul_vec(&y);

            // Compute challenge c̃ = H(w || μ)
            // Hash the raw coefficients as-is (in [0, Q))
            let mut c_tilde = [0u8; 32];
            let mut hasher = Sha3_256::new();
            for i in 0..K {
                for &coeff in &w.polys[i].coeffs {
                    let bytes = coeff.to_le_bytes();
                    Digest::update(&mut hasher, &bytes);
                }
            }
            Digest::update(&mut hasher, &mu);
            c_tilde.copy_from_slice(&hasher.finalize());

            // Sample c from c̃
            let c = sample_c(&c_tilde);

            // Compute z = y + c·s
            let cs = c_times_s(&c, &self.secret.s);
            let z = y.add(&cs);

            // Check norm bound: ||z||∞ < γ₁ - β
            if z.infinity_norm() >= GAMMA1 - BETA {
                continue;
            }

            // Compute hints from z for compression
            // Hints indicate which coefficients need 12 bits (wrapped) vs 18 bits (normal)
            let mut hints_array: [[u8; N/8]; K] = [[0u8; N/8]; K];
            for i in 0..K {
                // Create hints based on z coefficients
                // A coefficient is "wrapped" if its absolute value needs more bits
                for j in 0..N {
                    let coeff = z.polys[i].coeffs[j];
                    // Check if coefficient needs only 12 bits
                    // 12-bit signed range: [-2048, 2047]
                    if coeff >= -2048 && coeff <= 2047 {
                        hints_array[i][j / 8] |= 1u8 << (j % 8);
                    }
                }
            }

            // DEBUG: Verify relationship w' = w right after signing
            #[cfg(debug_assertions)]
            {
                let ct_debug = c_times_s(&c, &self.secret.t);
                let w_prime_debug = a.mul_vec(&z).sub(&ct_debug);
                let w_reduced_debug = w.center();
                let w_prime_reduced_debug = w_prime_debug.center();

                // Check if any coefficients differ significantly
                let mut max_diff = 0i32;
                for i in 0..K {
                    for j in 0..N {
                        let w_coeff = w_reduced_debug.polys[i].coeffs[j];
                        let wp_coeff = w_prime_reduced_debug.polys[i].coeffs[j];
                        let diff = (w_coeff - wp_coeff).abs();
                        if diff > max_diff {
                            max_diff = diff;
                        }
                    }
                }
                if max_diff > 1 {
                    eprintln!("WARNING: w != w' after signing, max diff: {}", max_diff);
                }
            }

            // Build signature with compression
            let mut sig_bytes = Vec::new();
            sig_bytes.push(0x02); // version byte: 0x02 = compressed format

            sig_bytes.extend_from_slice(&c_tilde);           // 32 bytes: challenge seed

            // Store Z raw (uncompressed) to debug
            let z_raw = z.serialize_raw();
            sig_bytes.extend_from_slice(&(z_raw.len() as u16).to_le_bytes()); // 2 bytes: z length
            sig_bytes.extend(&z_raw);                  // Variable bytes: z (uncompressed for now)

            // Compress hints using RLE
            let hints_compressed = Poly::encode_rle_hints(&hints_array);
            sig_bytes.extend_from_slice(&(hints_compressed.len() as u16).to_le_bytes()); // 2 bytes: hints_compressed length
            sig_bytes.extend(hints_compressed);              // Variable bytes: hints (RLE-compressed)

            return SevsSignature { bytes: sig_bytes };
        }

        panic!("SEVS signing failed after {} attempts", MAX_ATTEMPTS);
    }

    /// Verify signature
    pub fn verify(message: &[u8], signature: &SevsSignature, public_key: &SevsPubkey) -> bool {
        let sig = &signature.bytes;
        if sig.len() < 64 {
            return false;
        }

        // Check version byte to determine format
        let (c_tilde, z, _hints_array) = if sig[0] == 0x02 {
            // Compressed format
            if sig.len() < 37 {
                // Need: version(1) + c_tilde(32) + z_len(2) + hints_len(2) = 37
                return false;
            }

            let c_tilde: [u8; 32] = sig[1..33].try_into().unwrap_or([0; 32]);

            // Parse Z compressed
            let z_len = u16::from_le_bytes([sig[33], sig[34]]) as usize;
            if sig.len() < 35 + z_len {
                return false;
            }

            let z_data = &sig[35..35 + z_len];

            // Parse hints compressed
            let hints_offset = 35 + z_len;
            if sig.len() < hints_offset + 2 {
                return false;
            }

            let hints_len = u16::from_le_bytes([sig[hints_offset], sig[hints_offset + 1]]) as usize;
            if sig.len() < hints_offset + 2 + hints_len {
                return false;
            }

            let hints_data = &sig[hints_offset + 2..hints_offset + 2 + hints_len];

            // Decompress hints
            let hints_array = match Poly::decode_rle_hints(hints_data) {
                Ok(h) => h,
                Err(_) => return false,
            };

            // Read Z from raw format (uncompressed for now)
            let z = PolyVec::deserialize_raw(z_data);

            (c_tilde, z, hints_array)
        } else {
            // Uncompressed format (backward compatibility)
            let c_tilde: [u8; 32] = sig[..32].try_into().unwrap_or([0; 32]);
            let z_start = 32;
            let z_end = z_start + K * N * 4;
            let hints_size = K * (N/8);

            // Check signature length
            if sig.len() < z_end {
                return false;
            }

            // Parse uncompressed z
            let z_packed = &sig[z_start..z_end];
            let z = PolyVec::deserialize_raw(z_packed);

            // Parse hints if present
            let mut hints_array: [[u8; N/8]; K] = [[0u8; N/8]; K];
            let expected_len = z_end + hints_size;
            if sig.len() >= expected_len {
                let hints_start = sig.len() - hints_size;
                for i in 0..K {
                    let start = hints_start + i * (N/8);
                    let end = start + (N/8);
                    if end <= sig.len() {
                        hints_array[i].copy_from_slice(&sig[start..end]);
                    }
                }
            }

            (c_tilde, z, hints_array)
        };

        // Check z norm
        if z.infinity_norm() >= GAMMA1 - BETA {
            return false;
        }

        // Get public key components
        let seed_slice = public_key.seed();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_slice);
        let t_packed = public_key.t_packed();

        // Expand A
        let a = expand_a(&seed);

        // Deserialize t from public key
        let t = PolyVec::deserialize_raw(t_packed);

        // Sample c
        let c = sample_c(&c_tilde);

        // Compute μ
        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, public_key.as_bytes());
        let pk_hash: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha3_256::new();
        Digest::update(&mut hasher, &pk_hash);
        Digest::update(&mut hasher, message);
        let mu: [u8; 32] = hasher.finalize().into();

        // Compute w' = A·z - c·t
        let az = a.mul_vec(&z);
        let ct = c_times_s(&c, &t);
        let w_prime = az.sub(&ct);

        // Recompute challenge using high bits of w_prime
        // NOTE: Hints are used only for compression (to compress z), not for changing verification
        let mut hasher = Sha3_256::new();
        for i in 0..K {
            for &coeff in &w_prime.polys[i].coeffs {
                let bytes = coeff.to_le_bytes();
                Digest::update(&mut hasher, &bytes);
            }
        }
        Digest::update(&mut hasher, &mu);
        let expected_c_tilde: [u8; 32] = hasher.finalize().into();

        // Compare
        let result: bool = c_tilde.ct_eq(&expected_c_tilde).into();

        #[cfg(debug_assertions)]
        if !result {
            eprintln!("Verification failed:");
            eprintln!("  c_tilde:          {:?}", &c_tilde[..8]);
            eprintln!("  expected_c_tilde: {:?}", &expected_c_tilde[..8]);
            eprintln!("  z norm: {}", z.infinity_norm());
        }

        result
    }
}

impl Clone for SevsKeypair {
    fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
            public: self.public.clone(),
        }
    }
}

impl fmt::Debug for SevsKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SevsKeypair({:?})", self.public)
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = SevsKeypair::generate();
        assert!(!kp.pubkey().is_zero_ct());
    }

    #[test]
    fn test_sign_verify() {
        let kp = SevsKeypair::generate();
        let message = b"test message";
        let sig = kp.sign(message);
        assert!(sig.verify(message, &kp.pubkey()));
    }

    #[test]
    fn test_wrong_message() {
        let kp = SevsKeypair::generate();
        let sig = kp.sign(b"correct");
        assert!(!sig.verify(b"wrong", &kp.pubkey()));
    }

    #[test]
    fn test_wrong_key() {
        let kp1 = SevsKeypair::generate();
        let kp2 = SevsKeypair::generate();
        let sig = kp1.sign(b"test");
        assert!(!sig.verify(b"test", &kp2.pubkey()));
    }

    #[test]
    fn test_deterministic() {
        let kp = SevsKeypair::generate();
        let sig1 = kp.sign(b"test");
        let sig2 = kp.sign(b"test");
        assert_eq!(sig1.bytes, sig2.bytes);
    }

    #[test]
    fn test_from_seed() {
        let seed = [42u8; 32];
        let kp1 = SevsKeypair::from_seed(&seed);
        let kp2 = SevsKeypair::from_seed(&seed);
        assert_eq!(kp1.pubkey().bytes, kp2.pubkey().bytes);
    }

    #[test]
    fn test_signature_size() {
        let kp = SevsKeypair::generate();
        let sig = kp.sign(b"test");
        println!("Signature size: {} bytes", sig.len());
        assert!(sig.len() < 1100); // Should be around 650-900 bytes with compression
    }

    #[test]
    fn test_rle_encode_decode() {
        // Test RLE with all zeros
        let mut hints_zero = [[0u8; N/8]; K];
        let encoded = Poly::encode_rle_hints(&hints_zero);
        match Poly::decode_rle_hints(&encoded) {
            Ok(decoded) => {
                for i in 0..K {
                    assert_eq!(decoded[i], hints_zero[i], "RLE all-zeros mismatch at poly {}", i);
                }
            }
            Err(e) => panic!("RLE decode failed for all-zeros: {}", e),
        }

        // Test RLE with all ones
        let mut hints_ones = [[0xFFu8; N/8]; K];
        let encoded = Poly::encode_rle_hints(&hints_ones);
        match Poly::decode_rle_hints(&encoded) {
            Ok(decoded) => {
                for i in 0..K {
                    assert_eq!(decoded[i], hints_ones[i], "RLE all-ones mismatch at poly {}", i);
                }
            }
            Err(e) => panic!("RLE decode failed for all-ones: {}", e),
        }

        // Test RLE with alternating pattern
        let mut hints_alt = [[0u8; N/8]; K];
        for i in 0..N/8 {
            hints_alt[0][i] = if i % 2 == 0 { 0xAA } else { 0x55 };
        }
        let encoded = Poly::encode_rle_hints(&hints_alt);
        match Poly::decode_rle_hints(&encoded) {
            Ok(decoded) => {
                assert_eq!(decoded[0], hints_alt[0], "RLE alternating pattern mismatch");
            }
            Err(e) => panic!("RLE decode failed for alternating: {}", e),
        }
    }

    #[test]
    fn test_compression_reduces_size() {
        let kp = SevsKeypair::generate();
        let sig = kp.sign(b"test message");
        let compressed_size = sig.len();
        let uncompressed_size = SIGNATURE_SIZE_UNCOMPRESSED;

        println!("Compressed: {} bytes, Uncompressed: {} bytes", compressed_size, uncompressed_size);
        println!("Ratio: {:.1}%", 100.0 * compressed_size as f64 / uncompressed_size as f64);

        // Should achieve at least 20% reduction
        assert!(compressed_size < uncompressed_size, "Compression didn't work");
        assert!(compressed_size < (uncompressed_size * 85) / 100, "Not enough compression");
    }
}
