fn main() {
    println!("=== Z Compression Roundtrip Test ===\n");

    // Test value: positive number within expected Z range
    println!("Test 1: Positive value (1000)");
    test_z_compression(1000, 18, "normal");

    // Test value: negative number
    println!("\nTest 2: Negative value (-1000)");
    test_z_compression(-1000, 18, "normal");

    // Test wrapped small value (12 bits)
    println!("\nTest 3: Positive wrapped (100, 12 bits)");
    test_z_compression(100, 12, "wrapped");

    // Test wrapped negative (12 bits)
    println!("\nTest 4: Negative wrapped (-100, 12 bits)");
    test_z_compression(-100, 12, "wrapped");

    // Test edge case: maximum value for 18 bits signed
    // In 18-bit signed: range is [-2^17, 2^17-1] = [-131072, 131071]
    println!("\nTest 5: Maximum positive 18-bit (131071)");
    test_z_compression(131071, 18, "max");

    // Test minimum
    println!("\nTest 6: Minimum 18-bit (-131072)");
    test_z_compression(-131072, 18, "min");
}

fn test_z_compression(value: i32, bits: usize, label: &str) {
    println!("  Input value: {} ({} bits)", value, bits);

    // Pack
    let mask = (1i32 << bits) - 1;
    let masked = value & mask;
    let packed_as_u32 = masked as u32;

    println!("  Mask (2^{} - 1): 0x{:X}", bits, mask);
    println!("  Masked value: {}", masked);
    println!("  As u32: {} (0x{:X})", packed_as_u32, packed_as_u32);

    // Check sign bit
    let sign_bit = bits - 1;
    let has_sign = ((packed_as_u32 >> sign_bit) & 1) != 0;
    println!("  Bit {}: {} (sign bit is {})", sign_bit, (packed_as_u32 >> sign_bit) & 1, if has_sign { "SET" } else { "CLEAR" });

    // Unpack
    let mut unpacked = packed_as_u32 as i32;
    if has_sign {
        unpacked |= (-1) << bits;
    }

    println!("  Unpacked: {}", unpacked);

    if unpacked == value {
        println!("  ✓ ROUNDTRIP SUCCESSFUL");
    } else {
        println!("  ✗ ROUNDTRIP FAILED: got {} instead of {}", unpacked, value);
    }
}
