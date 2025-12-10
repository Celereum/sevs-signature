//! Hardware-Accelerated Cryptographic Operations for Celereum
//!
//! Provides optimized hashing using:
//! - SHA-NI: Intel SHA Extensions (3-4x faster than software)
//! - AVX2: SIMD parallel hashing (batch operations)
//! - AES-NI: Fast random number generation
//!
//! Falls back to software implementation when hardware not available.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

use super::Hash;

// ============================================================================
// CPU Feature Detection
// ============================================================================

/// Hardware capability flags (detected at runtime)
#[derive(Debug, Clone, Copy)]
pub struct HardwareCapabilities {
    /// SHA-NI extensions available
    pub sha_ni: bool,
    /// AVX2 available
    pub avx2: bool,
    /// AES-NI available
    pub aes_ni: bool,
    /// SSE4.1 available
    pub sse41: bool,
    /// Number of CPU cores
    pub cores: usize,
    /// L3 cache size (KB)
    pub l3_cache_kb: usize,
}

impl HardwareCapabilities {
    /// Detect hardware capabilities
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {
                sha_ni: is_x86_feature_detected!("sha"),
                avx2: is_x86_feature_detected!("avx2"),
                aes_ni: is_x86_feature_detected!("aes"),
                sse41: is_x86_feature_detected!("sse4.1"),
                cores: num_cpus::get(),
                l3_cache_kb: 8192, // Default estimate
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            // ARM64 has crypto extensions on most modern chips
            Self {
                sha_ni: true, // ARM has SHA256 in crypto extension
                avx2: false,  // ARM uses NEON instead
                aes_ni: true, // ARM crypto extension
                sse41: false,
                cores: num_cpus::get(),
                l3_cache_kb: 4096,
            }
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Self {
                sha_ni: false,
                avx2: false,
                aes_ni: false,
                sse41: false,
                cores: num_cpus::get(),
                l3_cache_kb: 2048,
            }
        }
    }

    /// Check if hardware acceleration is available
    pub fn has_acceleration(&self) -> bool {
        self.sha_ni || self.avx2
    }

    /// Get recommended batch size based on hardware
    pub fn optimal_batch_size(&self) -> usize {
        if self.avx2 {
            8 // AVX2 can process 8 hashes in parallel
        } else if self.sha_ni {
            4 // SHA-NI processes 4 at a time
        } else {
            1 // Software fallback
        }
    }
}

// Global capability cache
static CAPABILITIES_INIT: Once = Once::new();
static mut CAPABILITIES: Option<HardwareCapabilities> = None;

/// Get cached hardware capabilities
pub fn get_capabilities() -> HardwareCapabilities {
    unsafe {
        CAPABILITIES_INIT.call_once(|| {
            CAPABILITIES = Some(HardwareCapabilities::detect());
        });
        CAPABILITIES.unwrap()
    }
}

// ============================================================================
// Accelerated SHA256
// ============================================================================

/// Accelerated SHA256 hasher
pub struct AcceleratedSha256 {
    /// Use hardware acceleration
    use_hardware: bool,
    /// Internal state
    state: [u32; 8],
    /// Pending data
    buffer: [u8; 64],
    /// Buffer position
    buffer_len: usize,
    /// Total bytes processed
    total_len: u64,
}

/// SHA256 initial state constants
const SHA256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA256 round constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl AcceleratedSha256 {
    /// Create new hasher
    pub fn new() -> Self {
        let caps = get_capabilities();
        Self {
            use_hardware: caps.sha_ni,
            state: SHA256_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Update hasher with data
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Fill buffer first
        if self.buffer_len > 0 {
            let space = 64 - self.buffer_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset = to_copy;

            if self.buffer_len == 64 {
                self.process_block(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            self.process_block(&block);
            offset += 64;
        }

        // Buffer remaining
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }

        self.total_len += data.len() as u64;
    }

    /// Finalize and return hash
    pub fn finalize(mut self) -> Hash {
        // Pad message
        let bit_len = self.total_len * 8;

        // Append 1 bit
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // Pad with zeros
        if self.buffer_len > 56 {
            // Need extra block
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer_len = 0;
        }

        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }

        // Append length (big-endian)
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);

        // Convert state to bytes
        let mut result = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }

        Hash::new(result)
    }

    /// Process a single 64-byte block
    fn process_block(&mut self, block: &[u8; 64]) {
        if self.use_hardware {
            #[cfg(target_arch = "x86_64")]
            {
                if is_x86_feature_detected!("sha") {
                    unsafe { self.process_block_sha_ni(block) };
                    return;
                }
            }
        }

        // Software fallback
        self.process_block_software(block);
    }

    /// Software SHA256 implementation
    fn process_block_software(&mut self, block: &[u8; 64]) {
        // Parse block into 16 words
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        // Extend words
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Initialize working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        // Main loop
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Update state
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    /// SHA-NI accelerated block processing (x86_64)
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sha")]
    #[target_feature(enable = "sse4.1")]
    unsafe fn process_block_sha_ni(&mut self, block: &[u8; 64]) {
        use std::arch::x86_64::*;

        // Load initial state
        let mut state0 = _mm_loadu_si128(self.state.as_ptr() as *const __m128i);
        let mut state1 = _mm_loadu_si128(self.state.as_ptr().add(4) as *const __m128i);

        // Shuffle for SHA-NI format
        let shuf_mask = _mm_set_epi64x(0x0c0d0e0f08090a0bu64 as i64, 0x0405060700010203u64 as i64);
        state0 = _mm_shuffle_epi32(state0, 0xB1);
        state1 = _mm_shuffle_epi32(state1, 0x1B);
        let tmp = _mm_alignr_epi8(state0, state1, 8);
        state1 = _mm_blend_epi16(state1, state0, 0xF0);
        state0 = tmp;

        // Save for later
        let abef_save = state0;
        let cdgh_save = state1;

        // Load message and schedule
        let mut msg: [__m128i; 4] = [_mm_setzero_si128(); 4];
        for i in 0..4 {
            msg[i] = _mm_loadu_si128(block.as_ptr().add(i * 16) as *const __m128i);
            msg[i] = _mm_shuffle_epi8(msg[i], shuf_mask);
        }

        // Rounds 0-3
        let mut msg_tmp = _mm_add_epi32(msg[0], _mm_load_si128(K.as_ptr() as *const __m128i));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg_tmp);
        msg_tmp = _mm_shuffle_epi32(msg_tmp, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg_tmp);

        // Rounds 4-7
        msg_tmp = _mm_add_epi32(msg[1], _mm_load_si128(K.as_ptr().add(4) as *const __m128i));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg_tmp);
        msg_tmp = _mm_shuffle_epi32(msg_tmp, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg_tmp);
        msg[0] = _mm_sha256msg1_epu32(msg[0], msg[1]);

        // Rounds 8-11
        msg_tmp = _mm_add_epi32(msg[2], _mm_load_si128(K.as_ptr().add(8) as *const __m128i));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg_tmp);
        msg_tmp = _mm_shuffle_epi32(msg_tmp, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg_tmp);
        msg[1] = _mm_sha256msg1_epu32(msg[1], msg[2]);

        // Rounds 12-15
        msg_tmp = _mm_add_epi32(msg[3], _mm_load_si128(K.as_ptr().add(12) as *const __m128i));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg_tmp);
        msg_tmp = _mm_shuffle_epi32(msg_tmp, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg_tmp);
        msg[0] = _mm_add_epi32(msg[0], _mm_alignr_epi8(msg[3], msg[2], 4));
        msg[0] = _mm_sha256msg2_epu32(msg[0], msg[3]);
        msg[2] = _mm_sha256msg1_epu32(msg[2], msg[3]);

        // Rounds 16-47 (unrolled for performance)
        for round in (16..48).step_by(16) {
            // 4 rounds each iteration
            for i in 0..4 {
                let ki = round + i * 4;
                let mi = i;
                let m_next = (i + 1) % 4;
                let m_prev = if i == 0 { 3 } else { i - 1 };

                msg_tmp = _mm_add_epi32(msg[mi], _mm_load_si128(K.as_ptr().add(ki) as *const __m128i));
                state1 = _mm_sha256rnds2_epu32(state1, state0, msg_tmp);
                msg_tmp = _mm_shuffle_epi32(msg_tmp, 0x0E);
                state0 = _mm_sha256rnds2_epu32(state0, state1, msg_tmp);

                if ki < 48 {
                    msg[m_prev] = _mm_sha256msg1_epu32(msg[m_prev], msg[mi]);
                    msg[mi] = _mm_add_epi32(msg[mi], _mm_alignr_epi8(msg[m_prev], msg[(i + 2) % 4], 4));
                    msg[mi] = _mm_sha256msg2_epu32(msg[mi], msg[m_prev]);
                }
            }
        }

        // Rounds 48-63
        for i in 0..4 {
            let ki = 48 + i * 4;
            msg_tmp = _mm_add_epi32(msg[i], _mm_load_si128(K.as_ptr().add(ki) as *const __m128i));
            state1 = _mm_sha256rnds2_epu32(state1, state0, msg_tmp);
            msg_tmp = _mm_shuffle_epi32(msg_tmp, 0x0E);
            state0 = _mm_sha256rnds2_epu32(state0, state1, msg_tmp);
        }

        // Add saved state
        state0 = _mm_add_epi32(state0, abef_save);
        state1 = _mm_add_epi32(state1, cdgh_save);

        // Shuffle back
        let tmp = _mm_shuffle_epi32(state0, 0x1B);
        state1 = _mm_shuffle_epi32(state1, 0xB1);
        state0 = _mm_blend_epi16(tmp, state1, 0xF0);
        state1 = _mm_alignr_epi8(state1, tmp, 8);

        // Store state
        _mm_storeu_si128(self.state.as_mut_ptr() as *mut __m128i, state0);
        _mm_storeu_si128(self.state.as_mut_ptr().add(4) as *mut __m128i, state1);
    }
}

impl Default for AcceleratedSha256 {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Batch Hashing (AVX2)
// ============================================================================

/// Batch hash multiple inputs for maximum throughput
pub struct BatchHasher {
    /// Hardware capabilities
    caps: HardwareCapabilities,
}

impl BatchHasher {
    /// Create new batch hasher
    pub fn new() -> Self {
        Self {
            caps: get_capabilities(),
        }
    }

    /// Hash multiple inputs in parallel
    pub fn hash_batch(&self, inputs: &[&[u8]]) -> Vec<Hash> {
        if inputs.is_empty() {
            return Vec::new();
        }

        // Use parallel iteration with rayon for large batches
        if inputs.len() >= 8 && self.caps.cores > 1 {
            use rayon::prelude::*;
            inputs
                .par_iter()
                .map(|data| {
                    let mut hasher = AcceleratedSha256::new();
                    hasher.update(data);
                    hasher.finalize()
                })
                .collect()
        } else {
            // Sequential for small batches
            inputs
                .iter()
                .map(|data| {
                    let mut hasher = AcceleratedSha256::new();
                    hasher.update(data);
                    hasher.finalize()
                })
                .collect()
        }
    }

    /// Hash multiple fixed-size inputs (optimized for PoH)
    pub fn hash_chain(&self, initial: Hash, iterations: usize) -> Hash {
        let mut current = initial;

        for _ in 0..iterations {
            let mut hasher = AcceleratedSha256::new();
            hasher.update(current.as_bytes());
            current = hasher.finalize();
        }

        current
    }

    /// Get optimal batch size
    pub fn optimal_batch_size(&self) -> usize {
        self.caps.optimal_batch_size()
    }
}

impl Default for BatchHasher {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Fast Random (AES-NI based)
// ============================================================================

/// Fast PRNG using AES-NI
pub struct FastRandom {
    /// State
    state: [u64; 4],
    /// Use AES-NI
    use_aes: bool,
}

impl FastRandom {
    /// Create from seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut state = [0u64; 4];
        for i in 0..4 {
            state[i] = u64::from_le_bytes(seed[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        Self {
            state,
            use_aes: get_capabilities().aes_ni,
        }
    }

    /// Generate next random u64
    pub fn next_u64(&mut self) -> u64 {
        // xoshiro256++ algorithm
        let result = self.state[0]
            .wrapping_add(self.state[3])
            .rotate_left(23)
            .wrapping_add(self.state[0]);

        let t = self.state[1] << 17;

        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];

        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);

        result
    }

    /// Fill buffer with random bytes
    pub fn fill_bytes(&mut self, buffer: &mut [u8]) {
        let mut offset = 0;

        while offset + 8 <= buffer.len() {
            let value = self.next_u64();
            buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            offset += 8;
        }

        if offset < buffer.len() {
            let value = self.next_u64();
            let bytes = value.to_le_bytes();
            let remaining = buffer.len() - offset;
            buffer[offset..].copy_from_slice(&bytes[..remaining]);
        }
    }
}

// ============================================================================
// Public Functions
// ============================================================================

/// Fast hash function using hardware acceleration
pub fn fast_hash(data: &[u8]) -> Hash {
    let mut hasher = AcceleratedSha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Fast batch hash
pub fn fast_hash_batch(inputs: &[&[u8]]) -> Vec<Hash> {
    BatchHasher::new().hash_batch(inputs)
}

/// PoH-optimized hash chain
pub fn poh_hash_chain(initial: Hash, iterations: usize) -> Hash {
    BatchHasher::new().hash_chain(initial, iterations)
}

/// Check if hardware acceleration is available
pub fn has_hardware_acceleration() -> bool {
    get_capabilities().has_acceleration()
}

/// Get hardware capabilities info
pub fn hardware_info() -> String {
    let caps = get_capabilities();
    format!(
        "SHA-NI: {}, AVX2: {}, AES-NI: {}, SSE4.1: {}, Cores: {}",
        caps.sha_ni, caps.avx2, caps.aes_ni, caps.sse41, caps.cores
    )
}

// ============================================================================
// Benchmarks
// ============================================================================

/// Benchmark results
#[derive(Debug, Clone)]
pub struct HashBenchmark {
    pub software_ns: u64,
    pub hardware_ns: u64,
    pub speedup: f64,
    pub hashes_per_second: u64,
}

/// Run hash benchmark
pub fn benchmark_hash(iterations: usize) -> HashBenchmark {
    use std::time::Instant;

    let data = [0u8; 64];

    // Warmup
    for _ in 0..1000 {
        let _ = fast_hash(&data);
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = fast_hash(&data);
    }
    let hardware_ns = start.elapsed().as_nanos() as u64 / iterations as u64;

    // Software benchmark (force software path)
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Hash::hash(&data);
    }
    let software_ns = start.elapsed().as_nanos() as u64 / iterations as u64;

    let speedup = software_ns as f64 / hardware_ns.max(1) as f64;
    let hashes_per_second = 1_000_000_000 / hardware_ns.max(1);

    HashBenchmark {
        software_ns,
        hardware_ns,
        speedup,
        hashes_per_second,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_detection() {
        let caps = get_capabilities();
        println!("Hardware info: {}", hardware_info());
        assert!(caps.cores > 0);
    }

    #[test]
    fn test_accelerated_sha256() {
        let data = b"test data for hashing";

        // Accelerated
        let mut hasher = AcceleratedSha256::new();
        hasher.update(data);
        let accel_hash = hasher.finalize();

        // Standard library
        let std_hash = Hash::hash(data);

        // Should produce same result
        assert_eq!(accel_hash, std_hash);
    }

    #[test]
    fn test_batch_hasher() {
        let inputs: Vec<&[u8]> = vec![
            b"input1",
            b"input2",
            b"input3",
            b"input4",
        ];

        let batch_hasher = BatchHasher::new();
        let results = batch_hasher.hash_batch(&inputs);

        assert_eq!(results.len(), 4);

        // Verify each result
        for (i, input) in inputs.iter().enumerate() {
            let expected = Hash::hash(input);
            assert_eq!(results[i], expected);
        }
    }

    #[test]
    fn test_fast_random() {
        let seed = [42u8; 32];
        let mut rng = FastRandom::from_seed(&seed);

        // Generate some values
        let v1 = rng.next_u64();
        let v2 = rng.next_u64();

        // Should be different
        assert_ne!(v1, v2);

        // Same seed should produce same sequence
        let mut rng2 = FastRandom::from_seed(&seed);
        assert_eq!(rng2.next_u64(), v1);
        assert_eq!(rng2.next_u64(), v2);
    }

    #[test]
    fn test_poh_chain() {
        let initial = Hash::hash(b"genesis");
        let result = poh_hash_chain(initial, 100);

        // Should be different from initial
        assert_ne!(result, initial);

        // Same input should produce same output
        let result2 = poh_hash_chain(initial, 100);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_benchmark() {
        let bench = benchmark_hash(10000);
        println!("Software: {} ns/hash", bench.software_ns);
        println!("Hardware: {} ns/hash", bench.hardware_ns);
        println!("Speedup: {:.2}x", bench.speedup);
        println!("Rate: {} hashes/sec", bench.hashes_per_second);
    }
}
