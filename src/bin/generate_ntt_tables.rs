fn main() {
    const Q: i32 = 8380417;
    const N: usize = 128;
    const PRIMITIVE_ROOT: i32 = 5;

    println!("// ============================================================================");
    println!("// GENERATED NTT TWIDDLE FACTOR TABLES");
    println!("// Generated at compile time - paste into sevs.rs");
    println!("// ============================================================================\n");

    // Generate forward table
    println!("// Forward NTT twiddle factors");
    println!("const NTT_TWIDDLE_TABLE: &[&[i32]] = &[");

    let mut m = 1;
    while m < N {
        m *= 2;
        let w_exp = ((Q as u64 - 1) / (m as u64)) as u32;
        let w = mod_pow(PRIMITIVE_ROOT, w_exp, Q);

        print!("    &[");
        let mut wn = 1i32;
        for i in 0..m/2 {
            print!("{}", wn);
            if i < m/2 - 1 {
                print!(", ");
            }
            wn = ((wn as i64 * w as i64) % (Q as i64)) as i32;
        }
        println!("],");
    }
    println!("];\n");

    // Generate inverse table
    println!("// Inverse NTT twiddle factors");
    let inv_root_power = (Q as u32 - 2) as u32;
    let inv_primitive_root = mod_pow(PRIMITIVE_ROOT, inv_root_power, Q);

    println!("const NTT_INV_TWIDDLE_TABLE: &[&[i32]] = &[");

    let mut m = N;
    while m > 1 {
        m /= 2;
        let w_exp = ((Q as u64 - 1) / (m as u64)) as u32;
        let w = mod_pow(inv_primitive_root, w_exp, Q);

        print!("    &[");
        let mut wn = 1i32;
        for i in 0..m/2 {
            print!("{}", wn);
            if i < m/2 - 1 {
                print!(", ");
            }
            wn = ((wn as i64 * w as i64) % (Q as i64)) as i32;
        }
        println!("],");
    }
    // Add final stage for m=1 (single element [1])
    println!("    &[1],");
    println!("];\n");

    // Pre-computed constants
    let n_inv = mod_pow(N as i32, inv_root_power, Q);
    println!("// Pre-computed constants for inverse scaling");
    println!("const INV_PRIMITIVE_ROOT: i32 = {};", inv_primitive_root);
    println!("const N_INV: i32 = {};", n_inv);

    // Statistics
    println!("\n// Statistics:");
    println!("// Forward table stages: 7 (m = 2, 4, 8, 16, 32, 64, 128)");
    println!("// Inverse table stages: 7");
    println!("// Memory: ~7KB total");
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
