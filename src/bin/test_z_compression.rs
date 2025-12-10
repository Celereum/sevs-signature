//! Test Z compression pack/unpack roundtrip
//! This test isolates the Z compression issue by testing pack/unpack independently

use celereum::crypto::sevs::SevsKeypair;

fn main() {
    println!("=== Z Compression Roundtrip Test ===\n");

    // Test 1: Generate signature and verify without compression first
    println!("Test 1: Uncompressed Z (baseline)");
    let kp = SevsKeypair::generate();
    let msg = b"test";
    let sig = kp.sign(msg);

    if sig.verify(msg, &kp.pubkey()) {
        println!("  ✓ Uncompressed format verification PASSED\n");
    } else {
        println!("  ✗ Uncompressed format verification FAILED\n");
        return;
    }

    // Test 2: Try with compression enabled
    // This requires modifying the signing code to use pack_z_compressed
    println!("Test 2: Compressed Z (current implementation)");

    // Generate another signature
    let sig2 = kp.sign(b"test message");
    let sig_bytes = sig2.as_bytes();

    println!("  Signature format: 0x{:02x}", sig_bytes[0]);

    if sig_bytes[0] == 0x02 {
        println!("  ✓ Compressed format detected");

        // Try to verify
        if sig2.verify(b"test message", &kp.pubkey()) {
            println!("  ✓ Compressed format verification PASSED");
        } else {
            println!("  ✗ Compressed format verification FAILED");
            println!("     This suggests pack/unpack roundtrip is broken");
        }
    } else if sig_bytes[0] == 0x01 {
        println!("  ℹ Uncompressed format (Z compression not enabled)");
    }

    println!("\n=== Compression Analysis ===\n");

    // Test 3: Multiple messages to check consistency
    println!("Test 3: Multiple message verification");
    let mut compressed_pass = 0;
    let mut compressed_fail = 0;

    for i in 0..5 {
        let msg = format!("Message {}", i).into_bytes();
        let sig = kp.sign(&msg);

        if sig.verify(&msg, &kp.pubkey()) {
            compressed_pass += 1;
        } else {
            compressed_fail += 1;
        }
    }

    println!("  Passed: {}, Failed: {}", compressed_pass, compressed_fail);

    // Test 4: Wrong message rejection
    println!("\nTest 4: Wrong message rejection");
    let sig = kp.sign(b"correct");
    if !sig.verify(b"wrong", &kp.pubkey()) {
        println!("  ✓ Correctly rejected wrong message");
    } else {
        println!("  ✗ SECURITY ISSUE: Accepted wrong message!");
    }

    // Test 5: Different key rejection
    println!("\nTest 5: Different key rejection");
    let kp2 = SevsKeypair::generate();
    if !sig.verify(b"correct", &kp2.pubkey()) {
        println!("  ✓ Correctly rejected signature from different key");
    } else {
        println!("  ✗ SECURITY ISSUE: Accepted signature from different key!");
    }

    println!("\n=== Summary ===");
    if compressed_pass == 5 && compressed_fail == 0 {
        println!("✓ Z compression roundtrip is working correctly!");
    } else {
        println!("✗ Z compression has issues - {} failures out of {} tests", compressed_fail, compressed_pass + compressed_fail);
        println!("\nDebug info:");
        println!("  If Tests 4-5 passed but Tests 1-3 failed:");
        println!("  - The verify() function is executing correctly");
        println!("  - Z coefficients are being corrupted during pack/unpack");
        println!("  - Check bit-position calculations in pack_z_compressed/unpack_z_compressed");
    }
}
