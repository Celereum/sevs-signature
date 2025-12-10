//! Reference NTT implementation for correctness verification
//! Uses naive DFT (O(N²)) to verify NTT results

const Q: i32 = 8380417;
const N: usize = 4;
const PRIMITIVE_ROOT: i32 = 5;

fn main() {
    println!("=== NTT Reference Implementation ===\n");

    // Test vector
    let a = [1i32, 2i32, 3i32, 4i32];
    println!("Input: {:?}\n", a);

    // DFT (naive, mathematically correct)
    println!("=== Naive DFT (Reference) ===");
    let dft_a = naive_dft(&a);
    println!("DFT result: {:?}", dft_a);

    // IDFT (naive)
    println!("\n=== Naive IDFT (Reference) ===");
    let recovered = naive_idft(&dft_a);
    println!("IDFT result: {:?}", recovered);

    // Check roundtrip
    if a == recovered {
        println!("\n✓ Naive roundtrip SUCCESS");
    } else {
        println!("\n✗ Naive roundtrip FAILED");
        println!("  Expected: {:?}", a);
        println!("  Got:      {:?}", recovered);
    }

    // Now test with actual polynomial roots
    println!("\n\n=== Verify Polynomial Roots ===");
    verify_roots();
}

/// Naive DFT using definition: X[k] = Σ a[n] * ω^(kn)
fn naive_dft(a: &[i32; N]) -> [i32; N] {
    let mut result = [0i32; N];

    // ω = primitive_root^((Q-1)/N)
    let omega_exp = (Q as u64 - 1) / (N as u64);
    let omega = mod_pow(PRIMITIVE_ROOT, omega_exp as u32, Q);
    println!("  ω = primitive_root^((Q-1)/N) = {}^({}) mod Q", PRIMITIVE_ROOT, omega_exp);
    println!("    = {}", omega);

    for k in 0..N {
        let mut sum = 0i64;
        for n in 0..N {
            let power = (k * n) as u32;
            let wn = mod_pow(omega, power, Q);
            let prod = (a[n] as i64) * (wn as i64) % (Q as i64);
            sum = (sum + prod) % (Q as i64);
            if k == 0 && n < 3 {
                println!("  DFT[{}]: a[{}]*ω^({}*{}) = {} * {} = {}", k, n, k, n, a[n], wn, prod);
            }
        }
        result[k] = sum as i32;
        println!("  DFT[{}] = {}", k, result[k]);
    }
    result
}

/// Naive IDFT: a[n] = (1/N) * Σ X[k] * ω^(-kn)
fn naive_idft(x: &[i32; N]) -> [i32; N] {
    let mut result = [0i32; N];

    // ω^(-1) = (primitive_root)^(-(Q-1)/N) = (inv_primitive_root)^((Q-1)/N)
    let inv_root_power = (Q as u32 - 2) as u32;
    let inv_primitive_root = mod_pow(PRIMITIVE_ROOT, inv_root_power, Q);
    let omega_inv_exp = (Q as u64 - 1) / (N as u64);
    let omega_inv = mod_pow(inv_primitive_root, omega_inv_exp as u32, Q);
    println!("  ω^(-1) = inv_primitive_root^((Q-1)/N)");
    println!("    = {}", omega_inv);

    // 1/N mod Q
    let n_inv = mod_pow(N as i32, inv_root_power, Q);
    println!("  1/N mod Q = N^(Q-2) mod Q = {}", n_inv);

    for n in 0..N {
        let mut sum = 0i64;
        for k in 0..N {
            let power = (k * n) as u32;
            let wn_inv = mod_pow(omega_inv, power, Q);
            let prod = (x[k] as i64) * (wn_inv as i64) % (Q as i64);
            sum = (sum + prod) % (Q as i64);
            if n == 0 && k < 3 {
                println!("  IDFT[{}]: X[{}]*ω^(-{}*{}) = {} * {} = {}", n, k, k, n, x[k], wn_inv, prod);
            }
        }
        let scaled = (sum as i64 * n_inv as i64) % (Q as i64);
        result[n] = scaled as i32;
        if result[n] < 0 { result[n] += Q; }
        println!("  IDFT[{}] = {} * {} = {}", n, sum, n_inv, result[n]);
    }
    result
}

fn verify_roots() {
    println!("Checking if {} is a valid primitive root for N={}", PRIMITIVE_ROOT, N);

    // For primitive root: primitive_root^((Q-1)/2) ≡ -1 (mod Q)
    let half_order_exp = (Q as u32 - 1) / 2;
    let half_order_result = mod_pow(PRIMITIVE_ROOT, half_order_exp, Q);
    println!("  PRIMITIVE_ROOT^((Q-1)/2) = {}^({}) mod Q", PRIMITIVE_ROOT, half_order_exp);
    println!("    = {}", half_order_result);
    if half_order_result == Q as i32 - 1 {
        println!("  ✓ Verified: {} ≡ -1 (mod Q)", half_order_result);
    } else {
        println!("  ✗ NOT a primitive root!");
    }

    // For N-th root of unity: ω^N ≡ 1 (mod Q)
    let omega_exp = (Q as u64 - 1) / (N as u64);
    let omega = mod_pow(PRIMITIVE_ROOT, omega_exp as u32, Q);
    let omega_n = mod_pow(omega, N as u32, Q);
    println!("\n  ω = {}^({}) = {} mod Q", PRIMITIVE_ROOT, omega_exp, omega);
    println!("  ω^N = {}^{} mod Q", omega, N);
    println!("    = {}", omega_n);
    if omega_n == 1 {
        println!("  ✓ Verified: ω^N ≡ 1 (mod Q)");
    } else {
        println!("  ✗ NOT an N-th root of unity!");
    }
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
