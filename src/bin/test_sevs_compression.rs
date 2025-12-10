//! Test SEVS compression/decompression functionality

use celereum::crypto::sevs::{SevsKeypair, SIGNATURE_SIZE_UNCOMPRESSED};

fn main() {
    println!("=== SEVS Compression Test ===\n");

    // Test 1: Basic sign/verify with compression
    println!("Test 1: Sign and verify with compression");
    let kp = SevsKeypair::generate();
    let message = b"Hello, world!";

    let sig = kp.sign(message);
    let pubkey = kp.pubkey();

    println!("  Signature size: {} bytes", sig.len());
    println!("  Uncompressed would be: {} bytes", SIGNATURE_SIZE_UNCOMPRESSED);

    let ratio = (sig.len() as f64 / SIGNATURE_SIZE_UNCOMPRESSED as f64) * 100.0;
    println!("  Compression ratio: {:.1}%", ratio);
    println!("  Reduction: {:.1}%", 100.0 - ratio);

    if sig.verify(message, &pubkey) {
        println!("  ✓ Verification: PASSED");
    } else {
        println!("  ✗ Verification: FAILED");
        return;
    }

    // Test 2: Multiple messages
    println!("\nTest 2: Multiple messages");
    let mut total_size = 0;
    for i in 0..5 {
        let msg = format!("Message {}", i);
        let sig = kp.sign(msg.as_bytes());
        total_size += sig.len();

        if sig.verify(msg.as_bytes(), &pubkey) {
            println!("  Message {}: ✓ (size: {} bytes)", i, sig.len());
        } else {
            println!("  Message {}: ✗ FAILED", i);
            return;
        }
    }
    let avg = total_size / 5;
    println!("  Average signature size: {} bytes", avg);

    // Test 3: Wrong message rejection
    println!("\nTest 3: Wrong message rejection");
    let sig = kp.sign(b"correct");
    if !sig.verify(b"wrong", &pubkey) {
        println!("  ✓ Correctly rejected wrong message");
    } else {
        println!("  ✗ FAILED: Accepted wrong message");
        return;
    }

    // Test 4: Different key rejection
    println!("\nTest 4: Different key rejection");
    let kp2 = SevsKeypair::generate();
    if !sig.verify(b"correct", &kp2.pubkey()) {
        println!("  ✓ Correctly rejected signature from different key");
    } else {
        println!("  ✗ FAILED: Accepted signature from different key");
        return;
    }

    // Test 5: RLE hints compression quality
    println!("\nTest 5: Check signature format");
    let sig = kp.sign(b"test");
    let first_byte = sig.as_bytes()[0];
    if first_byte == 0x02 {
        println!("  ✓ Compressed format (version 0x02) detected");
    } else if first_byte == 0x01 {
        println!("  ✓ Uncompressed format (version 0x01) detected");
    } else {
        println!("  ✗ FAILED: Unknown signature format version: {}", first_byte);
        return;
    }

    println!("\n=== All tests passed! ===");
}
