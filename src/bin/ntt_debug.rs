//! Debug NTT transforms with minimal polynomials

use std::time::Instant;

fn main() {
    println!("=== NTT Debug ===\n");

    // Test with N=4 first
    println!("Testing 4-point NTT...");
    test_ntt_small();

    println!("\nTesting forward transform only (N=128)...");
    test_forward_only();
}

fn test_ntt_small() {
    const Q: i32 = 8380417;
    const N: usize = 4;
    const PRIMITIVE_ROOT: i32 = 5;

    // Simple polynomial: [1, 2, 3, 4]
    let mut a = [1i32, 2i32, 3i32, 4i32];
    println!("Input: {:?}", a);

    // Manual NTT for N=4
    // Bit-reversal for N=4: [0,1,2,3] -> [0,2,1,3]
    a.swap(1, 2);
    println!("After bit-reversal: {:?}", a);

    // Stage 1: m=2 (2-point DFT)
    // butterfly at (0,1) and (2,3)
    let w_exp = ((Q as u64 - 1) / 2u64) as u32;
    let w = mod_pow(PRIMITIVE_ROOT, w_exp, Q);
    println!("  Stage 1: w (for m=2) = {} (exp={})", w, w_exp);

    // Butterfly (0,1)
    let u = a[0];
    let v = (((a[1] as i64) * (w as i64)) % (Q as i64)) as i32;
    a[0] = ((u as i64 + v as i64) % (Q as i64)) as i32;
    if a[0] < 0 { a[0] += Q; }
    a[1] = ((u as i64 - v as i64) % (Q as i64)) as i32;
    if a[1] < 0 { a[1] += Q; }

    // Butterfly (2,3)
    let u = a[2];
    let v = (((a[3] as i64) * (w as i64)) % (Q as i64)) as i32;
    a[2] = ((u as i64 + v as i64) % (Q as i64)) as i32;
    if a[2] < 0 { a[2] += Q; }
    a[3] = ((u as i64 - v as i64) % (Q as i64)) as i32;
    if a[3] < 0 { a[3] += Q; }

    println!("After stage 1: {:?}", a);

    // Stage 2: m=4 (4-point DFT)
    let w_exp = ((Q as u64 - 1) / 4u64) as u32;
    let w0 = mod_pow(PRIMITIVE_ROOT, 0 * w_exp, Q);
    let w1 = mod_pow(PRIMITIVE_ROOT, 1 * w_exp, Q);
    println!("  Stage 2: w0={}, w1={} (exp={})", w0, w1, w_exp);

    // Butterfly (0,2) with w0
    let u = a[0];
    let v = (((a[2] as i64) * (w0 as i64)) % (Q as i64)) as i32;
    a[0] = ((u as i64 + v as i64) % (Q as i64)) as i32;
    if a[0] < 0 { a[0] += Q; }
    a[2] = ((u as i64 - v as i64) % (Q as i64)) as i32;
    if a[2] < 0 { a[2] += Q; }

    // Butterfly (1,3) with w1
    let u = a[1];
    let v = (((a[3] as i64) * (w1 as i64)) % (Q as i64)) as i32;
    a[1] = ((u as i64 + v as i64) % (Q as i64)) as i32;
    if a[1] < 0 { a[1] += Q; }
    a[3] = ((u as i64 - v as i64) % (Q as i64)) as i32;
    if a[3] < 0 { a[3] += Q; }

    println!("After stage 2 (NTT): {:?}\n", a);
}

fn test_forward_only() {
    const Q: i32 = 8380417;
    const N: usize = 128;

    // Simple input: all ones
    let a = [1i32; N];
    println!("Input: {} ones", N);

    let start = Instant::now();
    println!("Starting forward NTT...");

    // Just test bit-reversal
    let mut test = a.clone();
    let mut rev = 0usize;
    for i in 0..N {
        if i < rev {
            test.swap(i, rev);
        }
        let mut mask = N >> 1;
        while rev >= mask {
            rev -= mask;
            mask >>= 1;
        }
        rev += mask;
        if i < 5 || i >= N - 5 {
            println!("  i={}: rev after={}", i, rev);
        }
    }
    println!("Bit-reversal completed in {:.2} ms", start.elapsed().as_secs_f64() * 1000.0);

    // Test table access
    println!("\nTesting table access...");
    const NTT_TWIDDLE_TABLE: &[&[i32]] = &[
        &[1],
        &[1, 3572223],
        &[1, 3761513, 3572223, 3765607],
        &[1, 5234739, 3761513, 3201494, 3572223, 3201430, 3765607, 5496691],
        &[1, 4689127, 5234739, 1933895, 3761513, 5589936, 3201494, 3854230, 3572223, 5589481, 3201430, 4248187, 3765607, 2525786, 5496691, 7064191],
        &[1, 4122105, 4689127, 3048297, 5234739, 862698, 1933895, 7282116, 3761513, 7197530, 5589936, 5447654, 3201494, 5233158, 3854230, 2629187, 3572223, 5258194, 5589481, 1345413, 3201430, 5147234, 4248187, 3132183, 3765607, 3253310, 2525786, 5174631, 5496691, 1116786, 7064191, 1265186],
        &[1, 6535355, 4122105, 6008318, 4689127, 4486107, 3048297, 5371709, 5234739, 2241313, 862698, 5647980, 1933895, 6346667, 7282116, 7048702, 3761513, 1845269, 7197530, 4877596, 5589936, 3903894, 5447654, 6253949, 3201494, 5935422, 5233158, 4646862, 3854230, 4488587, 2629187, 2018318, 3572223, 7017898, 5258194, 4294549, 5589481, 4018627, 1345413, 7301006, 3201430, 1888372, 5147234, 6819405, 4248187, 5195707, 3132183, 6241206, 3765607, 1197654, 3253310, 5882004, 2525786, 6184511, 5174631, 1835214, 5496691, 7068631, 1116786, 6545086, 7064191, 4155418, 1265186, 6114886],
    ];

    for (stage, twiddles) in NTT_TWIDDLE_TABLE.iter().enumerate() {
        println!("  Stage {}: {} twiddles", stage, twiddles.len());
        if twiddles.len() > 0 {
            println!("    First: {}, Last: {}", twiddles[0], twiddles[twiddles.len() - 1]);
        }
    }

    println!("\nAll tests completed!");
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
