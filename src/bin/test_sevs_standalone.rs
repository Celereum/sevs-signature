//! Standalone test for SEVS compression/decompression debugging

use celereum::crypto::sevs::SevsKeypair;

fn main() {
    println!("=== SEVS Compression Debug Test ===\n");

    // Test 1: Basic compression/decompression
    println!("Test 1: Create signature and verify");
    let kp = SevsKeypair::generate();
    let message = b"Test message for compression";

    let sig = kp.sign(message);
    let pubkey = kp.pubkey();

    println!("  Signature created: {} bytes", sig.len());
    let sig_bytes = sig.as_bytes();
    println!("  First byte (format): 0x{:02x}", sig_bytes[0]);

    if sig_bytes[0] == 0x02 {
        println!("  ✓ Compressed format detected");

        // Extract structure
        if sig_bytes.len() >= 35 {
            let z_len = u16::from_le_bytes([sig_bytes[33], sig_bytes[34]]) as usize;
            let hints_offset = 35 + z_len;

            if sig_bytes.len() >= hints_offset + 2 {
                let hints_len = u16::from_le_bytes([sig_bytes[hints_offset], sig_bytes[hints_offset + 1]]) as usize;
                println!("  Structure: [1 byte version][32 bytes salt][2 bytes z_len][{} bytes z][2 bytes hints_len][{} bytes hints]", z_len, hints_len);
                println!("  Total: {} bytes", 1 + 32 + 2 + z_len + 2 + hints_len);
            }
        }
    } else if sig_bytes[0] == 0x01 {
        println!("  ℹ Uncompressed format (old format)");
    }

    // Test 2: Verify
    println!("\nTest 2: Verify signature");
    if sig.verify(message, &pubkey) {
        println!("  ✓ VERIFICATION PASSED");
    } else {
        println!("  ✗ VERIFICATION FAILED - debugging needed");

        // Let's try to narrow down where it fails
        println!("\nTest 2b: Check with uncompressed format");
        // Force uncompressed by creating another signature and checking format
    }

    // Test 3: Multiple messages
    println!("\nTest 3: Multiple messages");
    let mut failures = 0;
    for i in 0..3 {
        let msg = format!("Message {}", i);
        let sig = kp.sign(msg.as_bytes());

        if sig.verify(msg.as_bytes(), &pubkey) {
            println!("  Message {}: ✓ (size: {} bytes)", i, sig.len());
        } else {
            println!("  Message {}: ✗ FAILED", i);
            failures += 1;
        }
    }

    if failures > 0 {
        println!("\n⚠ {} verification failures - bug is consistent", failures);
    } else {
        println!("\n✓ All verifications passed!");
    }

    // Test 4: Wrong message should fail
    println!("\nTest 4: Wrong message rejection");
    let sig = kp.sign(b"correct");
    if !sig.verify(b"wrong", &pubkey) {
        println!("  ✓ Correctly rejected wrong message");
    } else {
        println!("  ✗ FAILED: Accepted wrong message (security issue!)");
    }

    // Test 5: Different key should fail
    println!("\nTest 5: Different key rejection");
    let kp2 = SevsKeypair::generate();
    if !sig.verify(b"correct", &kp2.pubkey()) {
        println!("  ✓ Correctly rejected signature from different key");
    } else {
        println!("  ✗ FAILED: Accepted signature from different key (security issue!)");
    }
}
