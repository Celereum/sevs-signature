//! State Compression Module
//!
//! Provides efficient compression for blockchain state to reduce:
//! - Storage requirements
//! - Network bandwidth
//! - Sync time
//!
//! Uses LZ4 for high-speed compression (pure Rust implementation).
//! Note: Zstd support requires native dependencies, enable via feature flag on Linux.

use serde::{Deserialize, Serialize};

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// LZ4 - Very fast, moderate compression (default)
    Lz4,
    /// LZ4 High Compression - Better ratio, still fast
    Lz4Hc,
}

impl Default for CompressionAlgorithm {
    fn default() -> Self {
        Self::Lz4
    }
}

/// Compression configuration
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Algorithm to use
    pub algorithm: CompressionAlgorithm,
    /// Minimum size to compress (smaller data is not worth compressing)
    pub min_size: usize,
    /// Enable parallel compression
    pub parallel: bool,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Lz4,
            min_size: 64,
            parallel: true,
        }
    }
}

impl CompressionConfig {
    /// High-speed configuration (for real-time operations)
    pub fn fast() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Lz4,
            min_size: 128,
            parallel: true,
        }
    }

    /// Higher compression configuration
    pub fn high_compression() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Lz4Hc,
            min_size: 32,
            parallel: true,
        }
    }
}

/// Compressed data wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedData {
    /// Original uncompressed size
    pub original_size: u32,
    /// Compressed size
    pub compressed_size: u32,
    /// Algorithm used
    pub algorithm: CompressionAlgorithm,
    /// Compressed bytes
    pub data: Vec<u8>,
}

impl CompressedData {
    /// Get compression ratio
    pub fn ratio(&self) -> f64 {
        if self.original_size == 0 {
            0.0
        } else {
            self.compressed_size as f64 / self.original_size as f64
        }
    }

    /// Get space savings percentage
    pub fn savings(&self) -> f64 {
        (1.0 - self.ratio()) * 100.0
    }
}

/// State compressor
pub struct StateCompressor {
    config: CompressionConfig,
}

impl StateCompressor {
    /// Create a new compressor with default config
    pub fn new() -> Self {
        Self::with_config(CompressionConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: CompressionConfig) -> Self {
        Self { config }
    }

    /// Compress data
    pub fn compress(&self, data: &[u8]) -> Result<CompressedData, CompressionError> {
        // Skip compression for small data
        if data.len() < self.config.min_size {
            return Ok(CompressedData {
                original_size: data.len() as u32,
                compressed_size: data.len() as u32,
                algorithm: CompressionAlgorithm::None,
                data: data.to_vec(),
            });
        }

        let compressed = match self.config.algorithm {
            CompressionAlgorithm::None => data.to_vec(),
            CompressionAlgorithm::Lz4 | CompressionAlgorithm::Lz4Hc => {
                self.compress_lz4(data)?
            }
        };

        // If compression didn't help, store uncompressed
        if compressed.len() >= data.len() {
            return Ok(CompressedData {
                original_size: data.len() as u32,
                compressed_size: data.len() as u32,
                algorithm: CompressionAlgorithm::None,
                data: data.to_vec(),
            });
        }

        Ok(CompressedData {
            original_size: data.len() as u32,
            compressed_size: compressed.len() as u32,
            algorithm: self.config.algorithm,
            data: compressed,
        })
    }

    /// Decompress data
    pub fn decompress(&self, compressed: &CompressedData) -> Result<Vec<u8>, CompressionError> {
        match compressed.algorithm {
            CompressionAlgorithm::None => Ok(compressed.data.clone()),
            CompressionAlgorithm::Lz4 | CompressionAlgorithm::Lz4Hc => {
                self.decompress_lz4(&compressed.data, compressed.original_size as usize)
            }
        }
    }

    /// Compress using LZ4 (very fast, pure Rust)
    fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>, CompressionError> {
        Ok(lz4_flex::compress_prepend_size(data))
    }

    /// Decompress LZ4
    fn decompress_lz4(&self, data: &[u8], _original_size: usize) -> Result<Vec<u8>, CompressionError> {
        lz4_flex::decompress_size_prepended(data)
            .map_err(|e| CompressionError::Decompress(e.to_string()))
    }

    /// Compress a serializable object
    pub fn compress_object<T: Serialize>(&self, obj: &T) -> Result<CompressedData, CompressionError> {
        let data = bincode::serialize(obj)
            .map_err(|e| CompressionError::Serialize(e.to_string()))?;
        self.compress(&data)
    }

    /// Decompress to an object
    pub fn decompress_object<T: for<'de> Deserialize<'de>>(
        &self,
        compressed: &CompressedData,
    ) -> Result<T, CompressionError> {
        let data = self.decompress(compressed)?;
        bincode::deserialize(&data)
            .map_err(|e| CompressionError::Deserialize(e.to_string()))
    }
}

impl Default for StateCompressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch compression for multiple items
pub struct BatchCompressor {
    compressor: StateCompressor,
}

impl BatchCompressor {
    pub fn new(config: CompressionConfig) -> Self {
        Self {
            compressor: StateCompressor::with_config(config),
        }
    }

    /// Compress multiple items in parallel
    pub fn compress_batch(&self, items: &[Vec<u8>]) -> Vec<Result<CompressedData, CompressionError>> {
        use rayon::prelude::*;

        items
            .par_iter()
            .map(|item| self.compressor.compress(item))
            .collect()
    }

    /// Decompress multiple items in parallel
    pub fn decompress_batch(
        &self,
        items: &[CompressedData],
    ) -> Vec<Result<Vec<u8>, CompressionError>> {
        use rayon::prelude::*;

        items
            .par_iter()
            .map(|item| self.compressor.decompress(item))
            .collect()
    }
}

/// Compression statistics
#[derive(Debug, Clone, Default)]
pub struct CompressionStats {
    pub total_original: u64,
    pub total_compressed: u64,
    pub items_compressed: u64,
    pub items_skipped: u64,
}

impl CompressionStats {
    pub fn add(&mut self, original: u64, compressed: u64, was_compressed: bool) {
        self.total_original += original;
        self.total_compressed += compressed;
        if was_compressed {
            self.items_compressed += 1;
        } else {
            self.items_skipped += 1;
        }
    }

    pub fn ratio(&self) -> f64 {
        if self.total_original == 0 {
            0.0
        } else {
            self.total_compressed as f64 / self.total_original as f64
        }
    }

    pub fn savings_mb(&self) -> f64 {
        (self.total_original - self.total_compressed) as f64 / 1_000_000.0
    }
}

impl std::fmt::Display for CompressionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Compression Stats:\n\
             - Original:    {:.2} MB\n\
             - Compressed:  {:.2} MB\n\
             - Ratio:       {:.1}%\n\
             - Savings:     {:.2} MB\n\
             - Compressed:  {} items\n\
             - Skipped:     {} items",
            self.total_original as f64 / 1_000_000.0,
            self.total_compressed as f64 / 1_000_000.0,
            self.ratio() * 100.0,
            self.savings_mb(),
            self.items_compressed,
            self.items_skipped
        )
    }
}

/// Compression errors
#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    #[error("Compression failed: {0}")]
    Compress(String),

    #[error("Decompression failed: {0}")]
    Decompress(String),

    #[error("Serialization failed: {0}")]
    Serialize(String),

    #[error("Deserialization failed: {0}")]
    Deserialize(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz4_compression() {
        let compressor = StateCompressor::with_config(CompressionConfig {
            algorithm: CompressionAlgorithm::Lz4,
            min_size: 0,
            ..Default::default()
        });

        let data = b"Hello, World! This is a test of LZ4 compression. ".repeat(100);
        let compressed = compressor.compress(&data).unwrap();

        assert!(compressed.compressed_size < compressed.original_size);
        assert_eq!(compressed.algorithm, CompressionAlgorithm::Lz4);

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);

        println!(
            "LZ4: {} -> {} bytes ({:.1}% savings)",
            data.len(),
            compressed.compressed_size,
            compressed.savings()
        );
    }

    #[test]
    fn test_skip_small_data() {
        let compressor = StateCompressor::with_config(CompressionConfig {
            algorithm: CompressionAlgorithm::Lz4,
            min_size: 100,
            ..Default::default()
        });

        let data = b"Small data";
        let compressed = compressor.compress(data).unwrap();

        assert_eq!(compressed.algorithm, CompressionAlgorithm::None);
        assert_eq!(compressed.data, data);
    }

    #[test]
    fn test_object_compression() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestObject {
            name: String,
            value: u64,
            data: Vec<u8>,
        }

        let compressor = StateCompressor::new();

        let obj = TestObject {
            name: "Test".repeat(100),
            value: 12345,
            data: vec![0u8; 1000],
        };

        let compressed = compressor.compress_object(&obj).unwrap();
        let decompressed: TestObject = compressor.decompress_object(&compressed).unwrap();

        assert_eq!(obj, decompressed);
    }

    #[test]
    fn test_batch_compression() {
        let batch = BatchCompressor::new(CompressionConfig::fast());

        let items: Vec<Vec<u8>> = (0..100)
            .map(|i| format!("Item {} data ", i).repeat(50).into_bytes())
            .collect();

        let compressed = batch.compress_batch(&items);
        assert_eq!(compressed.len(), 100);

        let compressed_data: Vec<_> = compressed.into_iter().map(|r| r.unwrap()).collect();
        let decompressed = batch.decompress_batch(&compressed_data);

        for (i, result) in decompressed.into_iter().enumerate() {
            assert_eq!(result.unwrap(), items[i]);
        }
    }
}
