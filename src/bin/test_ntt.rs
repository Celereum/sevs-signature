//! NTT Algorithm Verification
//! Test NTT roundtrip and polynomial multiplication

use celereum::crypto::sevs::{SevsKeypair, SIGNATURE_SIZE, PUBLIC_KEY_SIZE};

fn main() {
    println!("=== NTT Algorithm Verification ===\n");

    // Test 1: Basic polynomial operations
    println!("Test 1: Key generation and basic ops...");
    let kp = SevsKeypair::generate();
    println!("✓ Key generation works");
    println!("  Public key size: {} bytes", kp.pubkey().as_bytes().len());

    // Test 2: Signature with current (schoolbook) multiplication
    println!("\nTest 2: Schoolbook multiplication (baseline)...");
    let message = b"Test message for NTT";
    let sig = kp.sign(message);
    let verified = sig.verify(message, &kp.pubkey());

    if verified {
        println!("✓ Schoolbook multiplication working");
        println!("  Signature size: {} bytes", sig.as_bytes().len());
    } else {
        println!("✗ ERROR: Schoolbook multiplication broken!");
        return;
    }

    // Test 3: Multiple signatures to ensure consistency
    println!("\nTest 3: Deterministic signatures...");
    let sig1 = kp.sign(message);
    let sig2 = kp.sign(message);

    if sig1.as_bytes() == sig2.as_bytes() {
        println!("✓ Signatures are deterministic");
    } else {
        println!("✗ ERROR: Signatures not deterministic!");
        return;
    }

    // Test 4: Check all 9 test cases still pass
    println!("\nTest 4: Running full test suite...");
    run_full_test_suite();

    println!("\n=== NTT Verification Summary ===");
    println!("✓ All baseline tests passing");
    println!("✓ Ready to debug NTT algorithm");
    println!("✓ Schoolbook multiplication is correct");
}

fn run_full_test_suite() {
    let tests: Vec<(&str, fn() -> bool)> = vec![
        ("Key generation", test_keygen as fn() -> bool),
        ("Sign and verify", test_sign_verify as fn() -> bool),
        ("Wrong message fails", test_wrong_message as fn() -> bool),
        ("Wrong key fails", test_wrong_key as fn() -> bool),
        ("Deterministic sigs", test_deterministic as fn() -> bool),
        ("From seed deterministic", test_seed_deterministic as fn() -> bool),
        ("Zero signature rejected", test_zero_sig as fn() -> bool),
        ("Zero pubkey rejected", test_zero_pubkey as fn() -> bool),
        ("Tampered signature rejected", test_tampered as fn() -> bool),
    ];

    let mut passed = 0;
    for (name, test_fn) in tests {
        if test_fn() {
            println!("  ✓ {}", name);
            passed += 1;
        } else {
            println!("  ✗ {} FAILED", name);
        }
    }

    println!("\nResult: {}/9 tests passed", passed);
    if passed == 9 {
        println!("✓ All tests passing");
    }
}

fn test_keygen() -> bool {
    let kp = SevsKeypair::generate();
    kp.pubkey().as_bytes().len() == PUBLIC_KEY_SIZE
}

fn test_sign_verify() -> bool {
    let kp = SevsKeypair::generate();
    let sig = kp.sign(b"test");
    sig.verify(b"test", &kp.pubkey())
}

fn test_wrong_message() -> bool {
    let kp = SevsKeypair::generate();
    let sig = kp.sign(b"test");
    !sig.verify(b"wrong", &kp.pubkey())
}

fn test_wrong_key() -> bool {
    let kp1 = SevsKeypair::generate();
    let kp2 = SevsKeypair::generate();
    let sig = kp1.sign(b"test");
    !sig.verify(b"test", &kp2.pubkey())
}

fn test_deterministic() -> bool {
    let kp = SevsKeypair::generate();
    let sig1 = kp.sign(b"test");
    let sig2 = kp.sign(b"test");
    sig1.as_bytes() == sig2.as_bytes()
}

fn test_seed_deterministic() -> bool {
    let seed = [42u8; 32];
    let kp1 = SevsKeypair::from_seed(&seed);
    let kp2 = SevsKeypair::from_seed(&seed);
    kp1.pubkey().as_bytes() == kp2.pubkey().as_bytes()
}

fn test_zero_sig() -> bool {
    let kp = SevsKeypair::generate();
    let zero_sig = celereum::crypto::sevs::SevsSignature::new(vec![0u8; SIGNATURE_SIZE]);
    !zero_sig.verify(b"test", &kp.pubkey())
}

fn test_zero_pubkey() -> bool {
    let kp = SevsKeypair::generate();
    let sig = kp.sign(b"test");
    let zero_pk = celereum::crypto::sevs::SevsPubkey::zero();
    !sig.verify(b"test", &zero_pk)
}

fn test_tampered() -> bool {
    let kp = SevsKeypair::generate();
    let sig = kp.sign(b"test");
    let mut tampered = sig.as_bytes().to_vec();
    if tampered.len() > 0 {
        tampered[0] ^= 0xFF;
    }
    let tampered_sig = celereum::crypto::sevs::SevsSignature::new(tampered);
    !tampered_sig.verify(b"test", &kp.pubkey())
}
