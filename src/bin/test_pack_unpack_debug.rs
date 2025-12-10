//! Debug pack/unpack of Z coefficients
//! This helps identify exactly where Z coefficients get corrupted

use celereum::crypto::sevs::SevsKeypair;

fn main() {
    println!("=== Z Pack/Unpack Debug Test ===\n");

    // Create a signature to extract the Z polynomial
    let kp = SevsKeypair::generate();
    let msg = b"test";
    let sig = kp.sign(msg);

    // Check the signature format
    let sig_bytes = sig.as_bytes();
    println!("Signature format: 0x{:02x}", sig_bytes[0]);
    println!("Signature size: {} bytes\n", sig_bytes.len());

    // Extract Z and hints from the signature
    if sig_bytes[0] == 0x02 {
        let z_len = u16::from_le_bytes([sig_bytes[33], sig_bytes[34]]) as usize;
        let z_data = &sig_bytes[35..35 + z_len];

        let hints_offset = 35 + z_len;
        let hints_len = u16::from_le_bytes([sig_bytes[hints_offset], sig_bytes[hints_offset + 1]]) as usize;
        let hints_data = &sig_bytes[hints_offset + 2..hints_offset + 2 + hints_len];

        println!("Z data size: {} bytes", z_len);
        println!("Hints data size: {} bytes (compressed from 32 bytes)", hints_len);
        println!("Compression ratio for hints: {:.1}%\n", 100.0 * hints_len as f64 / 32.0);

        // Analyze the structure
        // Z should contain 2 polynomials * 128 coefficients * 4 bytes each = 1024 bytes (uncompressed)
        // But we're storing it raw, so it should be 1024 bytes
        println!("Expected Z size (2 polys * 128 coeffs * 4 bytes): 1024 bytes");
        println!("Actual Z size: {} bytes", z_len);

        if z_len == 1024 {
            println!("✓ Z is uncompressed (as expected)\n");
        } else {
            println!("✗ Z size mismatch!\n");
        }

        // Now test if we can pack/unpack with hints
        println!("Testing with full signature verification...");
        if sig.verify(msg, &kp.pubkey()) {
            println!("✓ Full verification passed\n");
            println!("This confirms the current implementation (raw Z + RLE hints) is working correctly.");
        } else {
            println!("✗ Full verification failed\n");
            println!("This indicates an issue in the verify path.");
        }
    }
}
