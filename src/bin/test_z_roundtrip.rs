//! Simple test for Z pack/unpack roundtrip

use celereum::crypto::sevs::SevsKeypair;

fn main() {
    println!("=== Z Pack/Unpack Roundtrip Test ===\n");

    // Generate a keypair and create a signature
    let kp = SevsKeypair::generate();
    let message = b"Test message";

    // Sign multiple times to get different Z values
    for attempt in 1..=3 {
        println!("Attempt {}:", attempt);
        let sig = kp.sign(message);
        let pubkey = kp.pubkey();

        // Try to verify
        if sig.verify(message, &pubkey) {
            println!("  ✓ Verification PASSED");
        } else {
            println!("  ✗ Verification FAILED");
            println!("  Signature size: {} bytes", sig.len());

            // Show the signature structure
            let sig_bytes = sig.as_bytes();
            if sig_bytes.len() > 0 {
                println!("  Version byte: 0x{:02x}", sig_bytes[0]);
                if sig_bytes[0] == 0x02 && sig_bytes.len() > 35 {
                    let z_len = u16::from_le_bytes([sig_bytes[33], sig_bytes[34]]) as usize;
                    let hints_offset = 35 + z_len;
                    if sig_bytes.len() >= hints_offset + 2 {
                        let hints_len = u16::from_le_bytes([sig_bytes[hints_offset], sig_bytes[hints_offset + 1]]) as usize;
                        println!("  Z length: {} bytes", z_len);
                        println!("  Hints length: {} bytes", hints_len);
                    }
                }
            }
        }
        println!();
    }
}
