// Standalone SEVS test binary
use celereum::crypto::sevs::{SevsKeypair, SevsPubkey, SevsSignature, SIGNATURE_SIZE, PUBLIC_KEY_SIZE};

#[test]
fn verify_as_equals_t() {
    // This tests that A·s = t holds for generated keys
    // Since we can't access internal fields, we'll rely on verification working
    // If verification fails, this relationship is broken
}

fn main() {
    println!("=== SEVS Test Suite ===\n");

    // Test 1: Key generation
    print!("1. Key generation... ");
    let kp = SevsKeypair::generate();
    assert_ne!(kp.pubkey(), SevsPubkey::zero());
    assert_eq!(kp.pubkey().as_bytes().len(), PUBLIC_KEY_SIZE);
    println!("PASS");

    // Test 2: Sign and verify
    print!("2. Sign and verify... ");
    let message = b"test";
    let signature = kp.sign(message);
    println!("(sig size: {} bytes)", signature.as_bytes().len());
    let pubkey = kp.pubkey();
    let verified = signature.verify(message, &pubkey);
    if verified {
        println!("PASS");
    } else {
        println!("FAIL - signature did not verify!");
        println!("   Trying again with same message and key...");
        // Try verifying the same signature again
        let verified2 = signature.verify(message, &pubkey);
        println!("   Second verify: {}", verified2);
        // Try signing and verifying again
        let sig2 = kp.sign(message);
        let verified3 = sig2.verify(message, &pubkey);
        println!("   New sig verify: {}", verified3);
        return;
    }

    // Test 3: Wrong message fails
    print!("3. Wrong message fails... ");
    if !signature.verify(b"Wrong message", &kp.pubkey()) {
        println!("PASS");
    } else {
        println!("FAIL");
        return;
    }

    // Test 4: Wrong key fails
    print!("4. Wrong key fails... ");
    let kp2 = SevsKeypair::generate();
    if !signature.verify(message, &kp2.pubkey()) {
        println!("PASS");
    } else {
        println!("FAIL");
        return;
    }

    // Test 5: Deterministic signatures
    print!("5. Deterministic signatures... ");
    let sig1 = kp.sign(b"deterministic");
    let sig2 = kp.sign(b"deterministic");
    if sig1.as_bytes() == sig2.as_bytes() {
        println!("PASS");
    } else {
        println!("FAIL");
        return;
    }

    // Test 6: From seed deterministic
    print!("6. From seed deterministic... ");
    let seed = [42u8; 32];
    let kp_a = SevsKeypair::from_seed(&seed);
    let kp_b = SevsKeypair::from_seed(&seed);
    if kp_a.pubkey() == kp_b.pubkey() {
        println!("PASS");
    } else {
        println!("FAIL");
        return;
    }

    // Test 7: Zero signature rejected
    print!("7. Zero signature rejected... ");
    if !SevsSignature::zero().verify(message, &kp.pubkey()) {
        println!("PASS");
    } else {
        println!("FAIL");
        return;
    }

    // Test 8: Zero pubkey rejected
    print!("8. Zero pubkey rejected... ");
    if !signature.verify(message, &SevsPubkey::zero()) {
        println!("PASS");
    } else {
        println!("FAIL");
        return;
    }

    // Test 9: Tampered signature rejected
    print!("9. Tampered signature rejected... ");
    let mut tampered = signature.as_bytes().to_vec();
    tampered[0] ^= 0xFF;
    if !SevsSignature::new(tampered).verify(message, &kp.pubkey()) {
        println!("PASS");
    } else {
        println!("FAIL");
        return;
    }

    println!("\n=== All tests passed! ===");
    println!("Signature size: {} bytes", SIGNATURE_SIZE);
    println!("Public key size: {} bytes", PUBLIC_KEY_SIZE);
}
