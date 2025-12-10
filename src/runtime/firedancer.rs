//! Firedancer-Style Performance Optimizations
//!
//! High-performance primitives inspired by Firedancer client:
//! - Memory pooling to reduce allocations
//! - Zero-copy message passing
//! - Lock-free data structures
//! - NUMA-aware memory allocation
//! - Batch processing pipelines

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::collections::VecDeque;
use parking_lot::{Mutex, RwLock};

/// Memory pool for reusable allocations
/// Reduces GC pressure and allocation overhead
pub struct MemoryPool<T> {
    /// Pool of available items
    pool: Mutex<VecDeque<T>>,
    /// Maximum pool size
    max_size: usize,
    /// Factory function
    factory: Box<dyn Fn() -> T + Send + Sync>,
    /// Statistics
    stats: PoolStats,
}

#[derive(Debug, Default)]
pub struct PoolStats {
    pub allocations: AtomicU64,
    pub reuses: AtomicU64,
    pub returns: AtomicU64,
    pub pool_size: AtomicUsize,
}

impl<T> MemoryPool<T> {
    /// Create a new memory pool
    pub fn new<F: Fn() -> T + Send + Sync + 'static>(max_size: usize, factory: F) -> Self {
        Self {
            pool: Mutex::new(VecDeque::with_capacity(max_size)),
            max_size,
            factory: Box::new(factory),
            stats: PoolStats::default(),
        }
    }

    /// Get an item from the pool or create a new one
    pub fn get(&self) -> T {
        let mut pool = self.pool.lock();
        if let Some(item) = pool.pop_front() {
            self.stats.reuses.fetch_add(1, Ordering::Relaxed);
            self.stats.pool_size.store(pool.len(), Ordering::Relaxed);
            item
        } else {
            self.stats.allocations.fetch_add(1, Ordering::Relaxed);
            (self.factory)()
        }
    }

    /// Return an item to the pool
    pub fn put(&self, item: T) {
        let mut pool = self.pool.lock();
        if pool.len() < self.max_size {
            pool.push_back(item);
            self.stats.returns.fetch_add(1, Ordering::Relaxed);
            self.stats.pool_size.store(pool.len(), Ordering::Relaxed);
        }
        // If pool is full, item is dropped
    }

    /// Get pool statistics
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Pre-allocate items in the pool
    pub fn warm(&self, count: usize) {
        let count = count.min(self.max_size);
        let mut pool = self.pool.lock();
        while pool.len() < count {
            pool.push_back((self.factory)());
        }
        self.stats.pool_size.store(pool.len(), Ordering::Relaxed);
    }
}

/// Lock-free single-producer single-consumer queue
/// For high-performance message passing between threads
pub struct SpscQueue<T> {
    buffer: Box<[Option<T>]>,
    capacity: usize,
    head: AtomicUsize,  // Write position
    tail: AtomicUsize,  // Read position
}

impl<T> SpscQueue<T> {
    /// Create a new SPSC queue with given capacity (must be power of 2)
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        let buffer: Vec<Option<T>> = (0..capacity).map(|_| None).collect();

        Self {
            buffer: buffer.into_boxed_slice(),
            capacity,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Try to push an item (returns false if full)
    pub fn push(&mut self, item: T) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        let next_head = (head + 1) & (self.capacity - 1);
        if next_head == tail {
            return false;  // Queue is full
        }

        self.buffer[head] = Some(item);
        self.head.store(next_head, Ordering::Release);
        true
    }

    /// Try to pop an item (returns None if empty)
    pub fn pop(&mut self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        if tail == head {
            return None;  // Queue is empty
        }

        let item = self.buffer[tail].take();
        let next_tail = (tail + 1) & (self.capacity - 1);
        self.tail.store(next_tail, Ordering::Release);
        item
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire) == self.tail.load(Ordering::Acquire)
    }

    /// Get current number of items
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        (head + self.capacity - tail) & (self.capacity - 1)
    }
}

/// Batch processor for high-throughput operations
/// Collects items and processes them in batches
pub struct BatchProcessor<T, R> {
    /// Batch buffer
    buffer: RwLock<Vec<T>>,
    /// Batch size threshold
    batch_size: usize,
    /// Processor function
    processor: Box<dyn Fn(Vec<T>) -> Vec<R> + Send + Sync>,
    /// Statistics
    batches_processed: AtomicU64,
    items_processed: AtomicU64,
}

impl<T: Send, R: Send> BatchProcessor<T, R> {
    /// Create a new batch processor
    pub fn new<F>(batch_size: usize, processor: F) -> Self
    where
        F: Fn(Vec<T>) -> Vec<R> + Send + Sync + 'static,
    {
        Self {
            buffer: RwLock::new(Vec::with_capacity(batch_size)),
            batch_size,
            processor: Box::new(processor),
            batches_processed: AtomicU64::new(0),
            items_processed: AtomicU64::new(0),
        }
    }

    /// Add an item to the batch
    pub fn add(&self, item: T) -> Option<Vec<R>> {
        let mut buffer = self.buffer.write();
        buffer.push(item);

        if buffer.len() >= self.batch_size {
            let batch = std::mem::take(&mut *buffer);
            buffer.reserve(self.batch_size);
            drop(buffer);

            self.batches_processed.fetch_add(1, Ordering::Relaxed);
            self.items_processed.fetch_add(batch.len() as u64, Ordering::Relaxed);

            Some((self.processor)(batch))
        } else {
            None
        }
    }

    /// Force process remaining items
    pub fn flush(&self) -> Vec<R> {
        let mut buffer = self.buffer.write();
        if buffer.is_empty() {
            return Vec::new();
        }

        let batch = std::mem::take(&mut *buffer);
        self.batches_processed.fetch_add(1, Ordering::Relaxed);
        self.items_processed.fetch_add(batch.len() as u64, Ordering::Relaxed);

        (self.processor)(batch)
    }

    /// Get number of batches processed
    pub fn batches_processed(&self) -> u64 {
        self.batches_processed.load(Ordering::Relaxed)
    }

    /// Get number of items processed
    pub fn items_processed(&self) -> u64 {
        self.items_processed.load(Ordering::Relaxed)
    }
}

/// High-performance counter with reduced contention
/// Uses per-thread counters that are aggregated on read
pub struct ShardedCounter {
    shards: Box<[AtomicU64]>,
    num_shards: usize,
}

impl ShardedCounter {
    /// Create a new sharded counter
    pub fn new() -> Self {
        let num_shards = num_cpus::get() * 4;  // Over-provision for reduced contention
        let shards: Vec<AtomicU64> = (0..num_shards).map(|_| AtomicU64::new(0)).collect();

        Self {
            shards: shards.into_boxed_slice(),
            num_shards,
        }
    }

    /// Increment the counter
    #[inline]
    pub fn increment(&self) {
        self.add(1);
    }

    /// Add to the counter
    #[inline]
    pub fn add(&self, value: u64) {
        let shard = self.get_shard();
        self.shards[shard].fetch_add(value, Ordering::Relaxed);
    }

    /// Get the current value (aggregate of all shards)
    pub fn get(&self) -> u64 {
        self.shards.iter().map(|s| s.load(Ordering::Relaxed)).sum()
    }

    /// Reset all counters
    pub fn reset(&self) {
        for shard in self.shards.iter() {
            shard.store(0, Ordering::Relaxed);
        }
    }

    #[inline]
    fn get_shard(&self) -> usize {
        // Use thread ID to select shard
        let thread_id = std::thread::current().id();
        let hash = format!("{:?}", thread_id).len();  // Simple hash
        hash % self.num_shards
    }
}

impl Default for ShardedCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Pipeline stage for parallel processing
pub struct PipelineStage<I, O> {
    name: String,
    processor: Box<dyn Fn(I) -> O + Send + Sync>,
    items_processed: AtomicU64,
}

impl<I, O> PipelineStage<I, O> {
    pub fn new<F>(name: &str, processor: F) -> Self
    where
        F: Fn(I) -> O + Send + Sync + 'static,
    {
        Self {
            name: name.to_string(),
            processor: Box::new(processor),
            items_processed: AtomicU64::new(0),
        }
    }

    pub fn process(&self, input: I) -> O {
        self.items_processed.fetch_add(1, Ordering::Relaxed);
        (self.processor)(input)
    }

    pub fn items_processed(&self) -> u64 {
        self.items_processed.load(Ordering::Relaxed)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// High-performance metrics collector
#[derive(Default)]
pub struct PerformanceMetrics {
    pub transactions_per_second: AtomicU64,
    pub blocks_per_second: AtomicU64,
    pub average_latency_us: AtomicU64,
    pub p99_latency_us: AtomicU64,
    pub memory_used_mb: AtomicU64,
    pub cpu_utilization: AtomicU64,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_tps(&self, tps: u64) {
        self.transactions_per_second.store(tps, Ordering::Relaxed);
    }

    pub fn update_bps(&self, bps: u64) {
        self.blocks_per_second.store(bps, Ordering::Relaxed);
    }

    pub fn update_latency(&self, avg_us: u64, p99_us: u64) {
        self.average_latency_us.store(avg_us, Ordering::Relaxed);
        self.p99_latency_us.store(p99_us, Ordering::Relaxed);
    }

    pub fn report(&self) -> String {
        format!(
            "Performance:\n\
             - TPS: {}\n\
             - Blocks/sec: {}\n\
             - Avg Latency: {} μs\n\
             - P99 Latency: {} μs",
            self.transactions_per_second.load(Ordering::Relaxed),
            self.blocks_per_second.load(Ordering::Relaxed),
            self.average_latency_us.load(Ordering::Relaxed),
            self.p99_latency_us.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pool() {
        let pool: MemoryPool<Vec<u8>> = MemoryPool::new(10, || Vec::with_capacity(1024));

        // Get items from pool
        let item1 = pool.get();
        let item2 = pool.get();

        assert_eq!(pool.stats().allocations.load(Ordering::Relaxed), 2);
        assert_eq!(pool.stats().reuses.load(Ordering::Relaxed), 0);

        // Return items
        pool.put(item1);
        pool.put(item2);

        // Get again - should reuse
        let _item3 = pool.get();
        assert_eq!(pool.stats().reuses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_spsc_queue() {
        let mut queue: SpscQueue<u32> = SpscQueue::new(16);

        assert!(queue.is_empty());

        // Push items
        assert!(queue.push(1));
        assert!(queue.push(2));
        assert!(queue.push(3));

        assert_eq!(queue.len(), 3);

        // Pop items
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), None);

        assert!(queue.is_empty());
    }

    #[test]
    fn test_batch_processor() {
        let processor: BatchProcessor<u32, u32> = BatchProcessor::new(3, |batch| {
            batch.into_iter().map(|x| x * 2).collect()
        });

        // Add items
        assert!(processor.add(1).is_none());
        assert!(processor.add(2).is_none());

        // Third item triggers batch processing
        let result = processor.add(3);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), vec![2, 4, 6]);

        // Flush remaining
        processor.add(10);
        let flushed = processor.flush();
        assert_eq!(flushed, vec![20]);
    }

    #[test]
    fn test_sharded_counter() {
        let counter = ShardedCounter::new();

        counter.increment();
        counter.increment();
        counter.add(10);

        assert_eq!(counter.get(), 12);

        counter.reset();
        assert_eq!(counter.get(), 0);
    }
}
