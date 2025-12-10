//! Test Z compression pack/unpack roundtrip

use celereum::crypto::sevs::SevsKeypair;

fn main() {
    println!("=== Z Pack/Unpack Roundtrip Test ===\n");

    // Create test data
    let kp = SevsKeypair::generate();
    let message = b"Test";
    let sig = kp.sign(message);
    let pubkey = kp.pubkey();

    // Test verify
    if sig.verify(message, &pubkey) {
        println!("✓ Verification PASSED - implementation is correct!");
        return;
    } else {
        println!("✗ Verification FAILED");
        println!("\nLikely causes:");
        println!("1. Pack/unpack roundtrip broken for signed values");
        println!("2. RLE encoding/decoding issue");
        println!("3. Hints mismatch between signing and verifying");
        println!("4. Z coefficient extraction logic broken");
    }
}
