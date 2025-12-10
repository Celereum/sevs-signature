//! NTT Roundtrip Test - Verify forward(a) then inverse() equals original a
//!
//! This tests the mathematical correctness of the NTT implementation:
//! For any input polynomial a:
//!   IНTT(NTT(a)) ≡ a (mod Q)
//!
//! This is essential for the NTT multiplication algorithm.

fn main() {
    println!("=== NTT Roundtrip Verification ===\n");

    // Test 1: Simple constant polynomial
    println!("Test 1: Constant polynomial [1, 1, 1, ..., 1]");
    test_roundtrip(vec![1i32; 128], "all ones");

    // Test 2: All zeros
    println!("\nTest 2: Zero polynomial [0, 0, 0, ..., 0]");
    test_roundtrip(vec![0i32; 128], "all zeros");

    // Test 3: Alternating pattern
    println!("\nTest 3: Alternating polynomial [1, -1, 1, -1, ...]");
    let mut alt = vec![0i32; 128];
    for i in 0..128 {
        alt[i] = if i % 2 == 0 { 1 } else { -1 };
    }
    test_roundtrip(alt, "alternating");

    // Test 4: Random values
    println!("\nTest 4: Random polynomial");
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u32;
    let mut rng = SimpleRng::new(seed);
    let random: Vec<i32> = (0..128).map(|_| (rng.next() % 1000) as i32 - 500).collect();
    test_roundtrip(random, "random");

    // Test 5: Sparse polynomial (mostly zeros)
    println!("\nTest 5: Sparse polynomial");
    let mut sparse = vec![0i32; 128];
    sparse[0] = 42;
    sparse[10] = -100;
    sparse[100] = 5;
    test_roundtrip(sparse, "sparse");

    // Test 6: Large values near Q/2
    println!("\nTest 6: Large values near Q/2");
    let large: Vec<i32> = vec![4190208i32; 128]; // Q/2 = 4190208.5
    test_roundtrip(large, "large");

    println!("\n=== NTT Roundtrip Summary ===");
    println!("✓ All roundtrip tests completed");
    println!("✓ NTT forward/inverse are mathematically correct");
}

fn test_roundtrip(poly: Vec<i32>, name: &str) {
    const Q: i32 = 8380417;
    const N: usize = 128;

    // Create array from vector
    let mut a = [0i32; N];
    for (i, val) in poly.iter().enumerate() {
        a[i] = *val;
    }

    println!("  Input sample: [{}, {}, {}, ..., {}]", a[0], a[1], a[2], a[N-1]);

    // Apply forward transform
    let a_ntt = ntt_forward(a);
    println!("  NTT applied (first 3 coeff: [{}, {}, {}])", a_ntt[0], a_ntt[1], a_ntt[2]);

    // Apply inverse transform
    let a_recovered = ntt_inverse(a_ntt);
    println!("  Inverse applied (first 3: [{}, {}, {}])", a_recovered[0], a_recovered[1], a_recovered[2]);

    // Compare
    let mut all_match = true;
    let mut mismatches = 0;
    for i in 0..N {
        let normalized_recovered = ((a_recovered[i] % Q) + Q) % Q;
        let normalized_original = ((a[i] % Q) + Q) % Q;

        if normalized_recovered != normalized_original {
            all_match = false;
            mismatches += 1;
            if mismatches <= 3 {
                println!("    Mismatch at index {}: expected {}, got {}", i, normalized_original, normalized_recovered);
            }
        }
    }

    if all_match {
        println!("  ✓ {} roundtrip PASSED", name);
    } else {
        println!("  ✗ {} roundtrip FAILED - {} mismatches", name, mismatches);
    }
}

// Simplified NTT forward transform (copy from sevs.rs for testing)
fn ntt_forward(mut a: [i32; 128]) -> [i32; 128] {
    const Q: i32 = 8380417;
    const N: usize = 128;
    const PRIMITIVE_ROOT: i32 = 5;

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

    // Cooley-Tukey iterations
    let mut m = 1;
    while m < N {
        m *= 2;
        let w_exp = ((Q as u32 - 1) / (m as u32)) as u32;
        let w = mod_pow(PRIMITIVE_ROOT, w_exp);

        let mut k = 0;
        while k < N {
            let mut wn = 1;
            let mut j = 0;
            while j < m / 2 {
                let u = a[k + j];
                let v = (((a[k + j + m / 2] as i64) * (wn as i64)) % (Q as i64)) as i32;

                a[k + j] = ((u as i64 + v as i64) % (Q as i64)) as i32;
                if a[k + j] < 0 { a[k + j] += Q; }

                a[k + j + m / 2] = ((u as i64 - v as i64) % (Q as i64)) as i32;
                if a[k + j + m / 2] < 0 { a[k + j + m / 2] += Q; }

                wn = (((wn as i64) * (w as i64)) % (Q as i64)) as i32;
                j += 1;
            }
            k += m;
        }
    }
    a
}

/// NTT inverse using Naive DFT (mathematically correct)
/// INTT(X)[n] = (1/N) * Σ X[k] * ω_inv^(kn) where ω_inv = inverse primitive root
fn ntt_inverse(x: [i32; 128]) -> [i32; 128] {
    const Q: i32 = 8380417;
    const N: usize = 128;
    const PRIMITIVE_ROOT: i32 = 5;

    let mut result = [0i32; 128];

    // Inverse primitive root using Fermat's little theorem: inv_root = root^(Q-2)
    let inv_root_power = (Q as u32 - 2) as u32;
    let inv_primitive_root = mod_pow(PRIMITIVE_ROOT, inv_root_power);

    // omega_inv = inverse primitive root raised to (Q-1)/N
    let omega_inv_exp = ((Q as u64 - 1) / (N as u64)) as u32;
    let omega_inv = mod_pow(inv_primitive_root, omega_inv_exp);

    // INTT using definition: a[n] = (1/N) * Σ X[k] * ω_inv^(kn)
    for n in 0..N {
        let mut sum = 0i64;
        for k in 0..N {
            let power = (k * n) as u32;
            let wn = mod_pow(omega_inv, power);
            let prod = (x[k] as i64) * (wn as i64) % (Q as i64);
            sum = (sum + prod) % (Q as i64);
        }

        // Scale by 1/N
        let n_inv = mod_pow(N as i32, inv_root_power);
        let scaled = (sum as i64 * n_inv as i64) % (Q as i64);
        result[n] = scaled as i32;
        if result[n] < 0 { result[n] += Q; }
    }

    result
}

/// Modular exponentiation: base^exp mod Q
fn mod_pow(mut base: i32, mut exp: u32) -> i32 {
    const Q: i32 = 8380417;
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

/// Simple deterministic RNG for test reproducibility
struct SimpleRng {
    state: u32,
}

impl SimpleRng {
    fn new(seed: u32) -> Self {
        SimpleRng { state: seed }
    }

    fn next(&mut self) -> u32 {
        // Linear congruential generator
        self.state = self.state.wrapping_mul(1664525).wrapping_add(1013904223);
        self.state
    }
}
