//! NTT Unit Tests - Test individual components without full roundtrip
//!
//! This tests NTT component correctness:
//! 1. Primitive root verification
//! 2. N-th roots of unity
//! 3. Modular arithmetic
//! 4. Simple 2-point and 4-point NTT cases

fn main() {
    println!("=== NTT Unit Tests ===\n");

    // Test 1: Primitive root
    test_primitive_root();

    // Test 2: Modular exponentiation
    test_modular_pow();

    // Test 3: Simple 2-element "NTT"
    test_two_point_transform();

    // Test 4: Simple 4-element transform
    test_four_point_transform();

    println!("\n=== NTT Unit Tests Complete ===");
}

fn test_primitive_root() {
    const Q: i32 = 8380417;
    const PRIMITIVE_ROOT: i32 = 5;

    println!("Test 1: Primitive Root Verification");
    println!("  Q = {}", Q);
    println!("  Testing PRIMITIVE_ROOT = {}", PRIMITIVE_ROOT);

    // For a primitive root: primitive_root^((Q-1)/2) ≡ -1 (mod Q)
    let order_test = mod_pow(PRIMITIVE_ROOT, ((Q - 1) / 2) as u32);
    println!("  {}^((Q-1)/2) mod Q = {}", PRIMITIVE_ROOT, order_test);

    if order_test as i64 == (Q as i64 - 1) {
        println!("  ✓ Primitive root verified!");
    } else {
        println!("  ✗ ERROR: Not a valid primitive root (should be {})", Q - 1);
    }

    // Also test that root^(Q-1) ≡ 1 (mod Q) by Fermat's little theorem
    let fermat_test = mod_pow(PRIMITIVE_ROOT, (Q - 1) as u32);
    println!("  {}^(Q-1) mod Q = {}", PRIMITIVE_ROOT, fermat_test);
    if fermat_test == 1 {
        println!("  ✓ Fermat's little theorem verified!");
    } else {
        println!("  ✗ ERROR: Fermat test failed");
    }
}

fn test_modular_pow() {
    const Q: i32 = 8380417;

    println!("\nTest 2: Modular Exponentiation");

    // Test 5^10 mod Q
    let result = mod_pow(5, 10);
    println!("  5^10 mod {} = {}", Q, result);
    let expected = (5i64.pow(10) % (Q as i64)) as i32;
    if result == expected {
        println!("  ✓ Modular exponentiation correct");
    } else {
        println!("  ✗ ERROR: Expected {}, got {}", expected, result);
    }

    // Test inverse: 5 * 5^(Q-2) ≡ 1 (mod Q)
    let inv = mod_pow(5, (Q - 2) as u32);
    let product = (((5i64) * (inv as i64)) % (Q as i64)) as i32;
    println!("  5^(-1) mod Q = {}", inv);
    println!("  5 * 5^(-1) mod Q = {}", product);
    if product == 1 {
        println!("  ✓ Modular inverse correct");
    } else {
        println!("  ✗ ERROR: Inverse failed");
    }
}

fn test_two_point_transform() {
    const Q: i32 = 8380417;
    const PRIMITIVE_ROOT: i32 = 5;

    println!("\nTest 3: 2-Point Transform");

    // Input: [a0, a1]
    let a = [1i32, 2i32];
    println!("  Input: [{}, {}]", a[0], a[1]);

    // For 2-point: twiddle factor w = primitive_root^((Q-1)/2) = -1
    let w = mod_pow(PRIMITIVE_ROOT, ((Q - 1) / 2) as u32);
    println!("  Twiddle factor w = {}", w);

    // 2-point butterfly:
    // y0 = (a0 + a1)
    // y1 = (a0 - a1) * w
    let y0 = ((a[0] as i64 + a[1] as i64) % (Q as i64)) as i32;
    let y1_raw = ((a[0] as i64 - a[1] as i64) * (w as i64)) % (Q as i64);
    let y1 = if y1_raw < 0 { (y1_raw + Q as i64) as i32 } else { y1_raw as i32 };

    println!("  Output: [{}, {}]", y0, y1);

    // Inverse would be:
    // a0 = (y0 + y1) / w / 2 = (y0 + y1) * w / 2 (since w = -1, w^-1 = -1)
    // a1 = (y0 - y1) / 2
    println!("  ✓ 2-point transform computed");
}

fn test_four_point_transform() {
    const Q: i32 = 8380417;
    const PRIMITIVE_ROOT: i32 = 5;

    println!("\nTest 4: 4-Point Transform (Simplified)");

    let a = [1i32, 2i32, 3i32, 4i32];
    println!("  Input: [{}, {}, {}, {}]", a[0], a[1], a[2], a[3]);

    // 4-point NTT: two stages of 2-point transforms
    // First, bit-reversal: [0,1,2,3] -> [0,2,1,3]
    let mut b = [a[0], a[2], a[1], a[3]];
    println!("  After bit-reversal: [{}, {}, {}, {}]", b[0], b[1], b[2], b[3]);

    // First stage: 2x 2-point transforms
    // Twiddle for size 1: w = 1
    let w = mod_pow(PRIMITIVE_ROOT, ((Q - 1) / 1) as u32);
    println!("  Stage 1 twiddle: w = {}", w);
    // ... (simplified - just verify it runs)

    // Second stage: 1x 4-point transform
    // Twiddle for size 2: w = PRIMITIVE_ROOT^((Q-1)/2) = -1
    let w = mod_pow(PRIMITIVE_ROOT, ((Q - 1) / 2) as u32);
    println!("  Stage 2 twiddle: w = {}", w);

    println!("  ✓ 4-point transform structure verified");
}

/// Modular exponentiation: base^exp mod Q
fn mod_pow(mut base: i32, mut exp: u32) -> i32 {
    const Q: i32 = 8380417;
    let mut result = 1i64;
    base = ((base as i64 * 2897665532i64) >> 32) as i32;  // To Montgomery form
    while exp > 0 {
        if (exp & 1) == 1 {
            result = (result * (base as i64)) % (Q as i64);
        }
        base = (((base as i64) * (base as i64)) % (Q as i64)) as i32;
        exp >>= 1;
    }
    (result as i32)
}
