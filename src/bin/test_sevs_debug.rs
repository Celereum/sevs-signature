//! Debug SEVS compression issues

use celereum::crypto::sevs::SevsKeypair;

fn main() {
    let kp = SevsKeypair::generate();
    let message = b"Test";

    let sig = kp.sign(message);
    let sig_bytes = sig.as_bytes();

    println!("Signature length: {} bytes", sig_bytes.len());
    println!("First 10 bytes (hex): {:02x?}", &sig_bytes[0..10.min(sig_bytes.len())]);
    println!("First byte: 0x{:02x}", sig_bytes[0]);

    if sig_bytes[0] == 0x02 {
        println!("Format: COMPRESSED (0x02)");
        println!("c_tilde would be at [1..33]: {:02x?}", &sig_bytes[1..33.min(sig_bytes.len())]);

        if sig_bytes.len() >= 35 {
            let z_len = u16::from_le_bytes([sig_bytes[33], sig_bytes[34]]) as usize;
            println!("z_len: {} bytes", z_len);
            println!("Would decompress z from [35..{}]", 35 + z_len);

            let hints_offset = 35 + z_len;
            if sig_bytes.len() >= hints_offset + 2 {
                let hints_len = u16::from_le_bytes([sig_bytes[hints_offset], sig_bytes[hints_offset + 1]]) as usize;
                println!("hints_offset: {}", hints_offset);
                println!("hints_len: {} bytes", hints_len);
                println!("Total expected: {} bytes", hints_offset + 2 + hints_len);
            }
        }
    } else if sig_bytes[0] < 32 {
        println!("Format: UNCOMPRESSED or UNKNOWN (first byte looks like data)");
    } else {
        println!("Format: UNKNOWN (first byte: 0x{:02x})", sig_bytes[0]);
    }

    // Try to verify
    let pubkey = kp.pubkey();
    if sig.verify(message, &pubkey) {
        println!("\n✓ Verification PASSED");
    } else {
        println!("\n✗ Verification FAILED");
    }
}
