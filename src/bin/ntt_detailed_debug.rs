//! Detailed NTT debugging - compare Cooley-Tukey with reference DFT step by step

const Q: i32 = 8380417;
const N: usize = 4;  // Small size for detailed debugging
const PRIMITIVE_ROOT: i32 = 5;

fn main() {
    println!("=== Detailed NTT vs DFT Comparison (N=4) ===\n");

    // Test input
    let input = [1i32, 2i32, 3i32, 4i32];
    println!("Input: {:?}\n", input);

    // Reference DFT (correct)
    println!("=== REFERENCE DFT (Correct) ===");
    let dft_result = naive_dft(&input);
    println!("DFT forward: {:?}\n", dft_result);

    let dft_recovered = naive_idft(&dft_result);
    println!("DFT inverse: {:?}", dft_recovered);
    println!("DFT roundtrip: {}\n", if input == dft_recovered { "✓ PASS" } else { "✗ FAIL" });

    // Cooley-Tukey NTT (broken)
    println!("=== COOLEY-TUKEY NTT (Broken) ===");
    let ntt_result = ntt_forward(input);
    println!("NTT forward: {:?}\n", ntt_result);

    let ntt_recovered = ntt_inverse(ntt_result);
    println!("NTT inverse: {:?}", ntt_recovered);
    println!("NTT roundtrip: {}\n", if input == ntt_recovered { "✓ PASS" } else { "✗ FAIL" });

    // Detailed comparison
    println!("=== DETAILED COMPARISON ===");
    println!("Forward DFT vs NTT:");
    for i in 0..N {
        let match_str = if dft_result[i] == ntt_result[i] { "✓" } else { "✗" };
        println!("  [{}]: DFT={:8} NTT={:8} {}", i, dft_result[i], ntt_result[i], match_str);
    }

    println!("\nInverse DFT vs NTT:");
    for i in 0..N {
        let match_str = if dft_recovered[i] == ntt_recovered[i] { "✓" } else { "✗" };
        println!("  [{}]: DFT={:8} NTT={:8} {}", i, dft_recovered[i], ntt_recovered[i], match_str);
    }

    // Check where they diverge
    println!("\n=== CHECKING BUTTERFLY OPERATIONS ===");
    debug_butterfly_comparison();
}

fn debug_butterfly_comparison() {
    // Manually verify butterfly operation
    let input = [1i32, 2i32, 3i32, 4i32];

    // Calculate twiddle factors manually
    let omega_exp = (Q as u64 - 1) / (N as u64);
    let omega = mod_pow(PRIMITIVE_ROOT, omega_exp as u32, Q);

    println!("Twiddle factors:");
    println!("  ω = {}^({}) mod {} = {}", PRIMITIVE_ROOT, omega_exp, Q, omega);

    // Stage 1: m=2 butterfly (should process pairs)
    println!("\nStage 1 (m=2) - Butterfly structure:");
    println!("  Should pair: (0,1) and (2,3)");
    println!("  Twiddle: w^0=1, w^0=1");

    // Expected butterfly for [1,2,3,4]:
    // Pair (1,2): u=1, v=2*1=2
    //   result[0] = (1+2) mod Q = 3
    //   result[1] = (1-2) mod Q = -1 mod Q = 8380416
    // Pair (3,4): u=3, v=4*1=4
    //   result[2] = (3+4) mod Q = 7
    //   result[3] = (3-4) mod Q = -1 mod Q = 8380416

    println!("\nAfter Stage 1 butterfly (before Stage 2):");
    println!("  Expected intermediate: [3, 8380416, 7, 8380416]");

    // Actually compute what NTT does
    let mut a = input;
    // Bit-reversal for N=4: 0->0, 1->2, 2->1, 3->3
    a.swap(1, 2);
    println!("  After bit-reversal: {:?}", a);

    // Stage 1
    {
        let m = 2;
        let w_exp = ((Q as u64 - 1) / (m as u64)) as u32;
        let w = mod_pow(PRIMITIVE_ROOT, w_exp, Q);
        println!("  Stage 1: m={}, w_exp={}, w={}", m, w_exp, w);

        for k in (0..N).step_by(m) {
            let mut wn = 1;
            for j in 0..m/2 {
                let u = a[k + j];
                let v = (((a[k + j + m / 2] as i64) * (wn as i64)) % (Q as i64)) as i32;

                println!("    Butterfly (k={}, j={}): u={}, wn={}, v={}", k, j, u, wn, v);
                println!("      a[{}] = ({} + {}) mod Q = {}", k+j, u, v, ((u as i64 + v as i64) % (Q as i64)) as i32);
                println!("      a[{}] = ({} - {}) mod Q = {}", k+j+m/2, u, v, ((u as i64 - v as i64) % (Q as i64)) as i32);

                a[k + j] = ((u as i64 + v as i64) % (Q as i64)) as i32;
                if a[k + j] < 0 { a[k + j] += Q; }

                a[k + j + m / 2] = ((u as i64 - v as i64) % (Q as i64)) as i32;
                if a[k + j + m / 2] < 0 { a[k + j + m / 2] += Q; }

                wn = (((wn as i64) * (w as i64)) % (Q as i64)) as i32;
            }
        }
    }

    println!("\n  After Stage 1: {:?}", a);
}

/// Naive DFT using definition: X[k] = Σ a[n] * ω^(kn)
fn naive_dft(a: &[i32; N]) -> [i32; N] {
    let mut result = [0i32; N];

    let omega_exp = (Q as u64 - 1) / (N as u64);
    let omega = mod_pow(PRIMITIVE_ROOT, omega_exp as u32, Q);

    for k in 0..N {
        let mut sum = 0i64;
        for n in 0..N {
            let power = (k * n) as u32;
            let wn = mod_pow(omega, power, Q);
            let prod = (a[n] as i64) * (wn as i64) % (Q as i64);
            sum = (sum + prod) % (Q as i64);
        }
        result[k] = sum as i32;
        if result[k] < 0 { result[k] += Q; }
    }
    result
}

/// Naive IDFT: a[n] = (1/N) * Σ X[k] * ω^(-kn)
fn naive_idft(x: &[i32; N]) -> [i32; N] {
    let mut result = [0i32; N];

    let inv_root_power = (Q as u32 - 2) as u32;
    let inv_primitive_root = mod_pow(PRIMITIVE_ROOT, inv_root_power, Q);
    let omega_inv_exp = (Q as u64 - 1) / (N as u64);
    let omega_inv = mod_pow(inv_primitive_root, omega_inv_exp as u32, Q);
    let n_inv = mod_pow(N as i32, inv_root_power, Q);

    for n in 0..N {
        let mut sum = 0i64;
        for k in 0..N {
            let power = (k * n) as u32;
            let wn_inv = mod_pow(omega_inv, power, Q);
            let prod = (x[k] as i64) * (wn_inv as i64) % (Q as i64);
            sum = (sum + prod) % (Q as i64);
        }
        let scaled = (sum as i64 * n_inv as i64) % (Q as i64);
        result[n] = scaled as i32;
        if result[n] < 0 { result[n] += Q; }
    }
    result
}

fn ntt_forward(mut a: [i32; N]) -> [i32; N] {
    // Bit-reversal
    let mut rev = 0usize;
    for i in 0..N {
        if i < rev {
            a.swap(i, rev);
        }
        let mut mask = N >> 1;
        while rev >= mask && mask > 0 {
            rev -= mask;
            mask >>= 1;
        }
        rev += mask;
    }

    // Cooley-Tukey
    let mut m = 1;
    while m < N {
        m *= 2;
        let w_exp = ((Q as u64 - 1) / (m as u64)) as u32;
        let w = mod_pow(PRIMITIVE_ROOT, w_exp, Q);

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

fn ntt_inverse(mut a: [i32; N]) -> [i32; N] {
    // DIF (Decimation-in-Frequency) inverse
    let inv_root_power = (Q as u32 - 2) as u32;
    let inv_primitive_root = mod_pow(PRIMITIVE_ROOT, inv_root_power, Q);
    let n_inv = mod_pow(N as i32, inv_root_power, Q);

    // DIF butterfly stages: process from small to large
    let mut m = 1;
    while m < N {
        m *= 2;
        let w_exp = ((Q as u64 - 1) / (m as u64)) as u32;
        let w = mod_pow(inv_primitive_root, w_exp, Q);

        let mut k = 0;
        while k < N {
            let mut wn = 1;
            let mut j = 0;
            while j < m / 2 {
                let u = a[k + j];
                let t = a[k + j + m / 2];

                // DIF butterfly
                let sum = ((u as i64 + t as i64) % (Q as i64)) as i32;
                let diff = ((u as i64 - t as i64) % (Q as i64)) as i32;

                a[k + j] = sum;
                if a[k + j] < 0 { a[k + j] += Q; }

                let prod = (((diff as i64) * (wn as i64)) % (Q as i64)) as i32;
                a[k + j + m / 2] = prod;
                if a[k + j + m / 2] < 0 { a[k + j + m / 2] += Q; }

                wn = (((wn as i64) * (w as i64)) % (Q as i64)) as i32;
                j += 1;
            }
            k += m;
        }
    }

    // Bit-reversal permutation
    let mut rev = 0usize;
    for i in 0..N {
        if i < rev {
            a.swap(i, rev);
        }
        let mut mask = N >> 1;
        while rev >= mask && mask > 0 {
            rev -= mask;
            mask >>= 1;
        }
        rev += mask;
    }

    // Final scaling by 1/N
    for coeff in &mut a {
        *coeff = (((*coeff as i64) * (n_inv as i64)) % (Q as i64)) as i32;
        if *coeff < 0 { *coeff += Q; }
    }
    a
}

fn mod_pow(mut base: i32, mut exp: u32, q: i32) -> i32 {
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
