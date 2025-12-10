//! Test NTT with N=4 (smallest non-trivial case)
//! This helps identify infinite loops quickly

use std::time::Instant;

const Q: i32 = 8380417;
const N: usize = 4;
const PRIMITIVE_ROOT: i32 = 5;

fn main() {
    println!("=== Small NTT Test (N=4) ===\n");

    // Simple test: [1, 2, 3, 4]
    let input = [1i32, 2i32, 3i32, 4i32];
    println!("Input: {:?}", input);

    println!("\n--- Testing Forward NTT ---");
    let start = Instant::now();
    let output = ntt_forward(input);
    let elapsed = start.elapsed();
    println!("✓ Forward NTT completed in {:.2}µs", elapsed.as_secs_f64() * 1_000_000.0);
    println!("Output: {:?}", output);

    println!("\n--- Testing Inverse NTT ---");
    let start = Instant::now();
    let recovered = ntt_inverse(output);
    let elapsed = start.elapsed();
    println!("✓ Inverse NTT completed in {:.2}µs", elapsed.as_secs_f64() * 1_000_000.0);
    println!("Recovered: {:?}", recovered);

    // Check roundtrip
    if input == recovered {
        println!("\n✓ ROUNDTRIP SUCCESS: NTT(INTT(a)) == a");
    } else {
        println!("\n✗ ROUNDTRIP FAILED");
        println!("  Expected: {:?}", input);
        println!("  Got:      {:?}", recovered);
    }
}

fn ntt_forward(mut a: [i32; N]) -> [i32; N] {
    println!("  [Forward] Starting bit-reversal");

    // Bit-reversal permutation
    let mut rev = 0usize;
    for i in 0..N {
        println!("    i={}, rev_before={}", i, rev);
        if i < rev {
            println!("    Swapping a[{}] <-> a[{}]", i, rev);
            a.swap(i, rev);
        }
        let mut mask = N >> 1;
        while rev >= mask && mask > 0 {  // FIXED: add mask > 0
            rev -= mask;
            mask >>= 1;
        }
        rev += mask;
        println!("    rev_after={}", rev);
    }

    println!("  [Forward] Bit-reversal complete: {:?}", a);

    // Cooley-Tukey iterations
    let mut stage = 0;
    let mut m = 1;
    while m < N {
        m *= 2;
        println!("  [Forward] Stage {} (m={})", stage, m);
        let w_exp = ((Q as u64 - 1) / (m as u64)) as u32;
        let w = mod_pow(PRIMITIVE_ROOT, w_exp, Q);
        println!("    w (m={}, exp={}) = {}", m, w_exp, w);

        let mut k = 0;
        let mut iter = 0;
        while k < N {
            println!("    k={} butterfly iteration {}", k, iter);
            let mut twiddle_idx = 0;
            let mut j = 0;
            while j < m / 2 {
                let u = a[k + j];
                let wn = if twiddle_idx == 0 { 1 } else { w };
                let v = (((a[k + j + m / 2] as i64) * (wn as i64)) % (Q as i64)) as i32;

                println!("      j={}: a[{}]={}, a[{}]={}, wn={}", j, k+j, u, k+j+m/2, a[k+j+m/2], wn);

                a[k + j] = ((u as i64 + v as i64) % (Q as i64)) as i32;
                if a[k + j] < 0 { a[k + j] += Q; }

                a[k + j + m / 2] = ((u as i64 - v as i64) % (Q as i64)) as i32;
                if a[k + j + m / 2] < 0 { a[k + j + m / 2] += Q; }

                println!("      Result: a[{}]={}, a[{}]={}", k+j, a[k+j], k+j+m/2, a[k+j+m/2]);

                twiddle_idx += 1;
                j += 1;
            }
            k += m;
            iter += 1;
        }
        stage += 1;
    }

    println!("  [Forward] Complete: {:?}", a);
    a
}

fn ntt_inverse(mut a: [i32; N]) -> [i32; N] {
    println!("  [Inverse] Starting inverse NTT");

    // Inverse primitive root
    let inv_root_power = (Q as u32 - 2) as u32;
    let inv_primitive_root = mod_pow(PRIMITIVE_ROOT, inv_root_power, Q);
    println!("  [Inverse] inv_primitive_root = {}", inv_primitive_root);

    // Cooley-Tukey iterations (top-down)
    let mut stage = 0;
    let mut m = N;
    while m > 1 {
        m /= 2;
        println!("  [Inverse] Stage {} (m={})", stage, m);
        let w_exp = ((Q as u64 - 1) / (m as u64)) as u32;
        let w = mod_pow(inv_primitive_root, w_exp, Q);
        println!("    w (m={}, exp={}) = {}", m, w_exp, w);

        let mut k = 0;
        let mut iter = 0;
        while k < N {
            println!("    k={} butterfly iteration {}", k, iter);
            let mut twiddle_idx = 0;
            let mut j = 0;
            while j < m / 2 {
                let u = a[k + j];
                let wn = if twiddle_idx == 0 { 1 } else { w };
                let v = (((a[k + j + m / 2] as i64) * (wn as i64)) % (Q as i64)) as i32;

                println!("      j={}: a[{}]={}, a[{}]={}, wn={}", j, k+j, u, k+j+m/2, a[k+j+m/2], wn);

                a[k + j] = ((u as i64 + v as i64) % (Q as i64)) as i32;
                if a[k + j] < 0 { a[k + j] += Q; }

                a[k + j + m / 2] = ((u as i64 - v as i64) % (Q as i64)) as i32;
                if a[k + j + m / 2] < 0 { a[k + j + m / 2] += Q; }

                println!("      Result: a[{}]={}, a[{}]={}", k+j, a[k+j], k+j+m/2, a[k+j+m/2]);

                twiddle_idx += 1;
                j += 1;
            }
            k += m;
            iter += 1;
        }
        stage += 1;
    }

    println!("  [Inverse] After butterflies: {:?}", a);

    // Bit-reversal at end
    println!("  [Inverse] Starting bit-reversal");
    let mut rev = 0usize;
    for i in 0..N {
        println!("    i={}, rev_before={}", i, rev);
        if i < rev {
            println!("    Swapping a[{}] <-> a[{}]", i, rev);
            a.swap(i, rev);
        }
        let mut mask = N >> 1;
        while rev >= mask && mask > 0 {  // FIXED: add mask > 0
            rev -= mask;
            mask >>= 1;
        }
        rev += mask;
        println!("    rev_after={}", rev);
    }

    println!("  [Inverse] After bit-reversal: {:?}", a);

    // Scale by 1/N
    let n_inv = mod_pow(N as i32, inv_root_power, Q);
    println!("  [Inverse] N_INV = {}", n_inv);
    for coeff in &mut a {
        *coeff = ((*coeff as i64) * (n_inv as i64) % (Q as i64)) as i32;
        if *coeff < 0 { *coeff += Q; }
    }

    println!("  [Inverse] After scaling: {:?}", a);
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
