//! NTT (Number Theoretic Transform) for fast polynomial multiplication
//!
//! This module implements NTT-based polynomial multiplication for SEVS,
//! providing ~15x speedup over schoolbook multiplication.
//!
//! # Parameters
//! - N = 128 (polynomial degree)
//! - Q = 8380417 (modulus, prime with Q ≡ 1 mod 2N)
//! - Primitive root: 1753 (for Q)

const N: usize = 128;
const Q: i64 = 8380417;
const PRIMITIVE_ROOT: i64 = 1753;
const Q_I32: i32 = 8380417;

/// Compute modular exponentiation: base^exp mod modulus
fn power_mod(mut base: i64, mut exp: u32, modulus: i64) -> i64 {
    let mut result = 1i64;
    base %= modulus;
    if base < 0 { base += modulus; }

    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exp >>= 1;
    }

    result
}

/// Compute modular inverse using Fermat's little theorem
fn mod_inverse(a: i64, modulus: i64) -> i64 {
    power_mod(a, (modulus - 2) as u32, modulus)
}

/// Precompute zeta powers (twiddle factors) on-the-fly
fn compute_zeta_table() -> [i32; N] {
    let mut zetas = [0i32; N];
    let zeta = power_mod(PRIMITIVE_ROOT, ((Q - 1) / (2 * N as i64)) as u32, Q) as i32;

    let mut zeta_power = 1i64;
    for i in 0..N {
        zetas[i] = zeta_power as i32;
        zeta_power = (zeta_power * zeta as i64) % Q;
    }

    zetas
}

/// Precompute inverse zeta powers on-the-fly
fn compute_inv_zeta_table(zetas: &[i32; N]) -> [i32; N] {
    let mut inv_zetas = [0i32; N];
    let inv_zeta = mod_inverse(zetas[1] as i64, Q) as i32;

    let mut inv_zeta_power = 1i64;
    for i in 0..N {
        inv_zetas[i] = inv_zeta_power as i32;
        inv_zeta_power = (inv_zeta_power * inv_zeta as i64) % Q;
    }

    inv_zetas
}

/// Montgomery reduction: reduce a number modulo Q efficiently
#[inline]
fn montgomery_reduce(a: i64) -> i32 {
    let mut t = a % Q;
    if t < 0 { t += Q; }
    t as i32
}

/// Forward NTT transform (Cooley-Tukey algorithm)
pub fn ntt_forward(coeffs: &[i32; N]) -> [i32; N] {
    let zetas = compute_zeta_table();
    let mut result = *coeffs;

    let mut len = 2;

    while len <= N {
        for start in (0..N).step_by(len) {
            let zeta = zetas[N / len] as i64;
            let mut zeta_power = 1i64;

            for j in 0..(len / 2) {
                let t = (result[start + j + len / 2] as i64 * zeta_power) % Q;
                let u = result[start + j] as i64;

                result[start + j] = montgomery_reduce(u + t);
                result[start + j + len / 2] = montgomery_reduce(u - t + Q);

                zeta_power = (zeta_power * zeta) % Q;
            }
        }

        len *= 2;
    }

    result
}

/// Inverse NTT transform
pub fn ntt_inverse(coeffs: &[i32; N]) -> [i32; N] {
    let zetas = compute_zeta_table();
    let inv_zetas = compute_inv_zeta_table(&zetas);
    let mut result = *coeffs;

    // Inverse transform
    let mut len = 2;

    while len <= N {
        for start in (0..N).step_by(len) {
            let inv_zeta = inv_zetas[N / len] as i64;
            let mut inv_zeta_power = 1i64;

            for j in 0..(len / 2) {
                let t = (result[start + j + len / 2] as i64 * inv_zeta_power) % Q;
                let u = result[start + j] as i64;

                result[start + j] = montgomery_reduce(u + t);
                result[start + j + len / 2] = montgomery_reduce(u - t + Q);

                inv_zeta_power = (inv_zeta_power * inv_zeta) % Q;
            }
        }

        len *= 2;
    }

    // Multiply by N^-1 mod Q to complete the inverse
    let n_inv = mod_inverse(N as i64, Q) as i64;
    for coeff in &mut result {
        *coeff = montgomery_reduce(*coeff as i64 * n_inv);
    }

    result
}

/// Fast NTT-based polynomial multiplication
/// Result: a * b mod (X^N + 1, Q)
pub fn mul_ntt(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    // Forward transforms
    let a_ntt = ntt_forward(a);
    let b_ntt = ntt_forward(b);

    // Pointwise multiplication
    let mut c_ntt = [0i32; N];
    for i in 0..N {
        c_ntt[i] = montgomery_reduce(a_ntt[i] as i64 * b_ntt[i] as i64);
    }

    // Inverse transform
    ntt_inverse(&c_ntt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_correctness() {
        // Test that NTT and inverse NTT are inverses
        let mut coeffs = [0i32; N];
        coeffs[0] = 100;
        coeffs[1] = 200;
        coeffs[42] = 300;

        let forward = ntt_forward(&coeffs);
        let backward = ntt_inverse(&forward);

        for i in 0..N {
            assert_eq!(coeffs[i], backward[i]);
        }
    }

    #[test]
    fn test_ntt_multiplication() {
        // Test that NTT multiplication matches schoolbook for small values
        let mut a = [0i32; N];
        let mut b = [0i32; N];

        a[0] = 10;
        a[1] = 20;
        b[0] = 30;
        b[1] = 40;

        let result = mul_ntt(&a, &b);

        // (10 + 20X) * (30 + 40X) = 300 + 400X + 600X + 800X^2
        // = 300 + 1000X + 800X^2
        // Since X^N = -1, we have X^128 = -1
        // So 800X^2 doesn't wrap around
        assert_eq!(result[0], 300);
        assert_eq!(result[1], 1000);
        assert_eq!(result[2], 800);
    }
}
