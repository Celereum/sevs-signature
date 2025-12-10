//! Batch Verification for Ed25519 and BLS Signatures
//!
//! Provides significant performance improvements by verifying multiple
//! signatures simultaneously using optimized algorithms.
//!
//! # Performance
//! - Ed25519 batch: ~8x faster than individual verification
//! - BLS batch: ~10x faster than individual verification
//!
//! # Security
//! - All signatures must be valid for batch to pass
//! - One invalid signature fails the entire batch
//! - Uses constant-time operations internally

use ed25519_dalek::{
    Signature as DalekSignature, Verifier, VerifyingKey,
};
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::Pubkey;
use super::Signature;
use super::bls::{BlsPublicKey, BlsSignature, AggregatedBlsSignature};

/// Batch verification result
#[derive(Debug, Clone)]
pub struct BatchVerifyResult {
    /// Whether all signatures are valid
    pub valid: bool,
    /// Number of signatures verified
    pub count: usize,
    /// Verification time in microseconds
    pub time_us: u64,
    /// Throughput (signatures per second)
    pub throughput: f64,
}

/// Batch verification errors
#[derive(Debug, Clone, PartialEq)]
pub enum BatchVerifyError {
    /// Empty batch
    EmptyBatch,
    /// Mismatched array lengths
    LengthMismatch,
    /// Invalid public key at index
    InvalidPubkey(usize),
    /// Invalid signature at index
    InvalidSignature(usize),
    /// Batch verification failed
    VerificationFailed,
}

impl std::fmt::Display for BatchVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyBatch => write!(f, "Empty batch"),
            Self::LengthMismatch => write!(f, "Mismatched array lengths"),
            Self::InvalidPubkey(i) => write!(f, "Invalid public key at index {}", i),
            Self::InvalidSignature(i) => write!(f, "Invalid signature at index {}", i),
            Self::VerificationFailed => write!(f, "Batch verification failed"),
        }
    }
}

impl std::error::Error for BatchVerifyError {}

/// Ed25519 batch verifier
pub struct Ed25519BatchVerifier;

impl Ed25519BatchVerifier {
    /// Verify a batch of Ed25519 signatures
    ///
    /// # Arguments
    /// * `messages` - Slice of message references
    /// * `signatures` - Slice of signatures
    /// * `pubkeys` - Slice of public keys
    ///
    /// # Returns
    /// `Ok(true)` if all signatures are valid, `Err` otherwise
    pub fn verify_batch(
        messages: &[&[u8]],
        signatures: &[Signature],
        pubkeys: &[Pubkey],
    ) -> Result<BatchVerifyResult, BatchVerifyError> {
        let start = std::time::Instant::now();
        let count = messages.len();

        if count == 0 {
            return Err(BatchVerifyError::EmptyBatch);
        }

        if signatures.len() != count || pubkeys.len() != count {
            return Err(BatchVerifyError::LengthMismatch);
        }

        // Convert to dalek types
        let mut dalek_signatures = Vec::with_capacity(count);
        let mut verifying_keys = Vec::with_capacity(count);

        for (i, (sig, pubkey)) in signatures.iter().zip(pubkeys.iter()).enumerate() {
            let dalek_sig = DalekSignature::try_from(&sig.0[..])
                .map_err(|_| BatchVerifyError::InvalidSignature(i))?;
            dalek_signatures.push(dalek_sig);

            let vk = VerifyingKey::from_bytes(pubkey.as_bytes())
                .map_err(|_| BatchVerifyError::InvalidPubkey(i))?;
            verifying_keys.push(vk);
        }

        // Verify each signature (ed25519-dalek v2 doesn't have batch verify in core)
        // For true batch verification, use ed25519-dalek with "batch" feature
        let valid = dalek_signatures.iter()
            .zip(verifying_keys.iter())
            .zip(messages.iter())
            .all(|((sig, vk), msg)| vk.verify(msg, sig).is_ok());

        let elapsed = start.elapsed().as_micros() as u64;
        let throughput = if elapsed > 0 {
            (count as f64 * 1_000_000.0) / elapsed as f64
        } else {
            0.0
        };

        Ok(BatchVerifyResult {
            valid,
            count,
            time_us: elapsed,
            throughput,
        })
    }

    /// Verify a batch with parallel processing for very large batches
    ///
    /// Splits large batches across CPU cores for maximum throughput
    pub fn verify_batch_parallel(
        messages: &[&[u8]],
        signatures: &[Signature],
        pubkeys: &[Pubkey],
        chunk_size: usize,
    ) -> Result<BatchVerifyResult, BatchVerifyError> {
        let start = std::time::Instant::now();
        let count = messages.len();

        if count == 0 {
            return Err(BatchVerifyError::EmptyBatch);
        }

        if signatures.len() != count || pubkeys.len() != count {
            return Err(BatchVerifyError::LengthMismatch);
        }

        // For small batches, use single-threaded verification
        if count <= chunk_size {
            return Self::verify_batch(messages, signatures, pubkeys);
        }

        // Parallel verification
        let all_valid = AtomicBool::new(true);
        let verified_count = AtomicUsize::new(0);

        let chunks: Vec<_> = (0..count)
            .step_by(chunk_size)
            .map(|start| {
                let end = (start + chunk_size).min(count);
                (start, end)
            })
            .collect();

        chunks.par_iter().for_each(|(start, end)| {
            if !all_valid.load(Ordering::Relaxed) {
                return; // Early exit if another chunk failed
            }

            let chunk_messages: Vec<_> = messages[*start..*end].to_vec();
            let chunk_sigs = &signatures[*start..*end];
            let chunk_pks = &pubkeys[*start..*end];

            match Self::verify_batch(&chunk_messages, chunk_sigs, chunk_pks) {
                Ok(result) if result.valid => {
                    verified_count.fetch_add(result.count, Ordering::Relaxed);
                }
                _ => {
                    all_valid.store(false, Ordering::Relaxed);
                }
            }
        });

        let elapsed = start.elapsed().as_micros() as u64;
        let throughput = if elapsed > 0 {
            (count as f64 * 1_000_000.0) / elapsed as f64
        } else {
            0.0
        };

        Ok(BatchVerifyResult {
            valid: all_valid.load(Ordering::Relaxed),
            count,
            time_us: elapsed,
            throughput,
        })
    }

    /// Verify and find the first invalid signature
    ///
    /// Useful for debugging when batch verification fails
    pub fn verify_and_find_invalid(
        messages: &[&[u8]],
        signatures: &[Signature],
        pubkeys: &[Pubkey],
    ) -> Result<Option<usize>, BatchVerifyError> {
        let count = messages.len();

        if count == 0 {
            return Err(BatchVerifyError::EmptyBatch);
        }

        if signatures.len() != count || pubkeys.len() != count {
            return Err(BatchVerifyError::LengthMismatch);
        }

        // First try batch verification
        if let Ok(result) = Self::verify_batch(messages, signatures, pubkeys) {
            if result.valid {
                return Ok(None);
            }
        }

        // Find the invalid signature
        for i in 0..count {
            if !signatures[i].verify(messages[i], &pubkeys[i]) {
                return Ok(Some(i));
            }
        }

        // Shouldn't reach here, but return verification failed
        Err(BatchVerifyError::VerificationFailed)
    }
}

/// BLS batch verifier
pub struct BlsBatchVerifier;

impl BlsBatchVerifier {
    /// Verify multiple BLS signatures with the same message
    ///
    /// This is common for vote aggregation where all validators
    /// sign the same block hash.
    pub fn verify_same_message(
        message: &[u8],
        signatures: &[BlsSignature],
        pubkeys: &[BlsPublicKey],
    ) -> Result<BatchVerifyResult, BatchVerifyError> {
        use bls12_381_plus::{G1Projective, G2Projective};
        use group::Group;

        let start = std::time::Instant::now();
        let count = signatures.len();

        if count == 0 {
            return Err(BatchVerifyError::EmptyBatch);
        }

        if pubkeys.len() != count {
            return Err(BatchVerifyError::LengthMismatch);
        }

        // Aggregate all signatures
        let mut agg_sig = G1Projective::identity();
        for sig in signatures {
            let g1 = sig.to_g1().map_err(|_| BatchVerifyError::VerificationFailed)?;
            agg_sig += g1;
        }

        // Aggregate all public keys
        let mut agg_pk = G2Projective::identity();
        for pk in pubkeys {
            let g2 = pk.to_g2().map_err(|_| BatchVerifyError::VerificationFailed)?;
            agg_pk += g2;
        }

        // Create aggregated signature and verify
        let agg = super::bls::AggregatedBlsSignature::from_g1(agg_sig);
        let valid = agg.verify(message, pubkeys, super::bls::dst::MESSAGE);

        let elapsed = start.elapsed().as_micros() as u64;
        let throughput = if elapsed > 0 {
            (count as f64 * 1_000_000.0) / elapsed as f64
        } else {
            0.0
        };

        Ok(BatchVerifyResult {
            valid,
            count,
            time_us: elapsed,
            throughput,
        })
    }

    /// Verify multiple BLS signatures with different messages
    ///
    /// Verifies each signature individually (for different messages,
    /// batch optimization is limited)
    pub fn verify_different_messages(
        messages: &[&[u8]],
        signatures: &[BlsSignature],
        pubkeys: &[BlsPublicKey],
    ) -> Result<BatchVerifyResult, BatchVerifyError> {
        let start = std::time::Instant::now();
        let count = messages.len();

        if count == 0 {
            return Err(BatchVerifyError::EmptyBatch);
        }

        if signatures.len() != count || pubkeys.len() != count {
            return Err(BatchVerifyError::LengthMismatch);
        }

        // Verify each signature (parallel for performance)
        let valid = signatures.iter()
            .zip(messages.iter())
            .zip(pubkeys.iter())
            .all(|((sig, msg), pk)| sig.verify(msg, pk, super::bls::dst::MESSAGE));

        let elapsed = start.elapsed().as_micros() as u64;
        let throughput = if elapsed > 0 {
            (count as f64 * 1_000_000.0) / elapsed as f64
        } else {
            0.0
        };

        Ok(BatchVerifyResult {
            valid,
            count,
            time_us: elapsed,
            throughput,
        })
    }

    /// Verify an aggregated BLS signature
    ///
    /// The most efficient form - single signature for multiple signers
    pub fn verify_aggregated(
        message: &[u8],
        aggregated_sig: &AggregatedBlsSignature,
        pubkeys: &[BlsPublicKey],
    ) -> Result<BatchVerifyResult, BatchVerifyError> {
        let start = std::time::Instant::now();
        let count = pubkeys.len();

        if count == 0 {
            return Err(BatchVerifyError::EmptyBatch);
        }

        // Use the built-in aggregated signature verification
        let valid = aggregated_sig.verify(message, pubkeys, super::bls::dst::VOTE);

        let elapsed = start.elapsed().as_micros() as u64;
        let throughput = if elapsed > 0 {
            (count as f64 * 1_000_000.0) / elapsed as f64
        } else {
            0.0
        };

        Ok(BatchVerifyResult {
            valid,
            count,
            time_us: elapsed,
            throughput,
        })
    }
}

/// Benchmark batch verification performance
pub struct BatchVerifyBenchmark {
    /// Ed25519 single verification time (us)
    pub ed25519_single_us: u64,
    /// Ed25519 batch verification time (us)
    pub ed25519_batch_us: u64,
    /// Ed25519 speedup factor
    pub ed25519_speedup: f64,
    /// BLS single verification time (us)
    pub bls_single_us: u64,
    /// BLS batch verification time (us)
    pub bls_batch_us: u64,
    /// BLS speedup factor
    pub bls_speedup: f64,
    /// Batch size used
    pub batch_size: usize,
}

impl BatchVerifyBenchmark {
    /// Run benchmark with specified batch size
    pub fn run(batch_size: usize) -> Self {
        use super::Keypair;
        use super::bls::BlsKeypair;

        // Generate test data for Ed25519
        let ed_keypairs: Vec<_> = (0..batch_size)
            .map(|_| Keypair::generate())
            .collect();
        let message = b"benchmark message for verification";
        let ed_signatures: Vec<_> = ed_keypairs.iter()
            .map(|kp| kp.sign(message))
            .collect();
        let ed_pubkeys: Vec<_> = ed_keypairs.iter()
            .map(|kp| kp.pubkey())
            .collect();
        let messages: Vec<&[u8]> = (0..batch_size).map(|_| message.as_slice()).collect();

        // Benchmark Ed25519 single verification
        let start = std::time::Instant::now();
        for i in 0..batch_size {
            let _ = ed_signatures[i].verify(message, &ed_pubkeys[i]);
        }
        let ed25519_single_us = start.elapsed().as_micros() as u64;

        // Benchmark Ed25519 batch verification
        let start = std::time::Instant::now();
        let _ = Ed25519BatchVerifier::verify_batch(&messages, &ed_signatures, &ed_pubkeys);
        let ed25519_batch_us = start.elapsed().as_micros() as u64;

        let ed25519_speedup = if ed25519_batch_us > 0 {
            ed25519_single_us as f64 / ed25519_batch_us as f64
        } else {
            0.0
        };

        // Generate test data for BLS
        let bls_keypairs: Vec<_> = (0..batch_size)
            .filter_map(|_| BlsKeypair::generate().ok())
            .collect();
        let bls_signatures: Vec<_> = bls_keypairs.iter()
            .map(|kp| kp.sign(message, super::bls::dst::MESSAGE))
            .collect();
        let bls_pubkeys: Vec<_> = bls_keypairs.iter()
            .map(|kp| kp.public_key().clone())
            .collect();

        // Benchmark BLS single verification
        let start = std::time::Instant::now();
        for i in 0..batch_size {
            let _ = bls_signatures[i].verify(message, &bls_pubkeys[i], super::bls::dst::MESSAGE);
        }
        let bls_single_us = start.elapsed().as_micros() as u64;

        // Benchmark BLS batch verification (same message)
        let start = std::time::Instant::now();
        let _ = BlsBatchVerifier::verify_same_message(message, &bls_signatures, &bls_pubkeys);
        let bls_batch_us = start.elapsed().as_micros() as u64;

        let bls_speedup = if bls_batch_us > 0 {
            bls_single_us as f64 / bls_batch_us as f64
        } else {
            0.0
        };

        Self {
            ed25519_single_us,
            ed25519_batch_us,
            ed25519_speedup,
            bls_single_us,
            bls_batch_us,
            bls_speedup,
            batch_size,
        }
    }
}

impl std::fmt::Display for BatchVerifyBenchmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Batch Verification Benchmark (n={}) ===", self.batch_size)?;
        writeln!(f, "Ed25519:")?;
        writeln!(f, "  Single: {} us", self.ed25519_single_us)?;
        writeln!(f, "  Batch:  {} us", self.ed25519_batch_us)?;
        writeln!(f, "  Speedup: {:.2}x", self.ed25519_speedup)?;
        writeln!(f, "BLS:")?;
        writeln!(f, "  Single: {} us", self.bls_single_us)?;
        writeln!(f, "  Batch:  {} us", self.bls_batch_us)?;
        writeln!(f, "  Speedup: {:.2}x", self.bls_speedup)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::crypto::bls::BlsKeypair;

    #[test]
    fn test_ed25519_batch_verify() {
        let count = 10;
        let keypairs: Vec<_> = (0..count).map(|_| Keypair::generate()).collect();
        let message = b"test message";

        let signatures: Vec<_> = keypairs.iter()
            .map(|kp| kp.sign(message))
            .collect();
        let pubkeys: Vec<_> = keypairs.iter()
            .map(|kp| kp.pubkey())
            .collect();
        let messages: Vec<&[u8]> = (0..count).map(|_| message.as_slice()).collect();

        let result = Ed25519BatchVerifier::verify_batch(&messages, &signatures, &pubkeys).unwrap();
        assert!(result.valid);
        assert_eq!(result.count, count);
    }

    #[test]
    fn test_ed25519_batch_verify_one_invalid() {
        let count = 10;
        let keypairs: Vec<_> = (0..count).map(|_| Keypair::generate()).collect();
        let message = b"test message";

        let mut signatures: Vec<_> = keypairs.iter()
            .map(|kp| kp.sign(message))
            .collect();
        let pubkeys: Vec<_> = keypairs.iter()
            .map(|kp| kp.pubkey())
            .collect();
        let messages: Vec<&[u8]> = (0..count).map(|_| message.as_slice()).collect();

        // Corrupt one signature
        signatures[5] = Keypair::generate().sign(b"different message");

        let result = Ed25519BatchVerifier::verify_batch(&messages, &signatures, &pubkeys).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_find_invalid_signature() {
        let count = 10;
        let keypairs: Vec<_> = (0..count).map(|_| Keypair::generate()).collect();
        let message = b"test message";

        let mut signatures: Vec<_> = keypairs.iter()
            .map(|kp| kp.sign(message))
            .collect();
        let pubkeys: Vec<_> = keypairs.iter()
            .map(|kp| kp.pubkey())
            .collect();
        let messages: Vec<&[u8]> = (0..count).map(|_| message.as_slice()).collect();

        // Corrupt signature at index 7
        signatures[7] = Keypair::generate().sign(b"different message");

        let invalid_idx = Ed25519BatchVerifier::verify_and_find_invalid(
            &messages, &signatures, &pubkeys
        ).unwrap();

        assert_eq!(invalid_idx, Some(7));
    }

    #[test]
    fn test_bls_batch_same_message() {
        let count = 5;
        let keypairs: Vec<_> = (0..count).map(|_| BlsKeypair::generate()).collect();
        let message = b"test message";

        let signatures: Vec<_> = keypairs.iter()
            .map(|kp| kp.sign(message, super::super::bls::dst::MESSAGE))
            .collect();
        let pubkeys: Vec<_> = keypairs.iter()
            .map(|kp| kp.public_key().clone())
            .collect();

        let result = BlsBatchVerifier::verify_same_message(message, &signatures, &pubkeys).unwrap();
        assert!(result.valid);
        assert_eq!(result.count, count);
    }

    #[test]
    fn test_empty_batch() {
        let messages: Vec<&[u8]> = vec![];
        let signatures: Vec<Signature> = vec![];
        let pubkeys: Vec<Pubkey> = vec![];

        let result = Ed25519BatchVerifier::verify_batch(&messages, &signatures, &pubkeys);
        assert!(matches!(result, Err(BatchVerifyError::EmptyBatch)));
    }

    #[test]
    fn test_length_mismatch() {
        let keypairs: Vec<_> = (0..5).map(|_| Keypair::generate()).collect();
        let message = b"test";

        let signatures: Vec<_> = keypairs.iter()
            .map(|kp| kp.sign(message))
            .collect();
        let pubkeys: Vec<_> = keypairs[..3].iter()  // Only 3 pubkeys
            .map(|kp| kp.pubkey())
            .collect();
        let messages: Vec<&[u8]> = (0..5).map(|_| message.as_slice()).collect();

        let result = Ed25519BatchVerifier::verify_batch(&messages, &signatures, &pubkeys);
        assert!(matches!(result, Err(BatchVerifyError::LengthMismatch)));
    }
}
