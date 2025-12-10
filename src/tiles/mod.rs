//! Tile Architecture - Firedancer-inspired Process Isolation
//!
//! Tiles are independent processing units that communicate via shared memory queues.
//! Each tile handles a specific task (networking, signature verification, execution, etc.)
//!
//! ## Benefits
//! - **Isolation**: If one tile crashes, others continue
//! - **Parallelism**: Each tile runs on its own thread/core
//! - **Pipeline**: Data flows through tiles in a pipeline
//! - **Bounded Memory**: Each tile has fixed memory allocation
//!
//! ## Tile Types
//! - `NetTile`: Network I/O (receive/send packets)
//! - `SigVerifyTile`: Signature verification
//! - `BankTile`: Transaction execution
//! - `PohTile`: Proof of History generation
//! - `ShredTile`: Block shredding and FEC encoding
//!
//! ## Communication
//! Tiles communicate via lock-free SPSC (Single Producer Single Consumer) queues.
//! Each queue has a fixed capacity and uses atomic operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};

use crate::core::{Block, Transaction};
use crate::crypto::Hash;
use crate::crypto::Pubkey;

// =============================================================================
// TILE IDENTIFIERS
// =============================================================================

/// Unique identifier for a tile
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TileId(pub u64);

impl TileId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Well-known tile IDs
    pub const NET_TILE: TileId = TileId(1);
    pub const SIG_VERIFY_TILE: TileId = TileId(2);
    pub const BANK_TILE: TileId = TileId(3);
    pub const POH_TILE: TileId = TileId(4);
    pub const SHRED_TILE: TileId = TileId(5);
}

// =============================================================================
// TILE CONFIGURATION
// =============================================================================

/// Configuration for a tile
#[derive(Debug, Clone)]
pub struct TileConfig {
    /// Tile ID
    pub id: TileId,
    /// Human-readable name
    pub name: String,
    /// Input queue capacity
    pub input_queue_size: usize,
    /// Output queue capacity
    pub output_queue_size: usize,
    /// CPU core affinity (optional)
    pub cpu_affinity: Option<usize>,
    /// Memory limit in bytes
    pub memory_limit: usize,
    /// Priority (higher = more important)
    pub priority: u8,
}

impl Default for TileConfig {
    fn default() -> Self {
        Self {
            id: TileId(0),
            name: "unnamed".to_string(),
            input_queue_size: 10_000,
            output_queue_size: 10_000,
            cpu_affinity: None,
            memory_limit: 256 * 1024 * 1024, // 256 MB
            priority: 0,
        }
    }
}

// =============================================================================
// TILE MESSAGE
// =============================================================================

/// Message passed between tiles
#[derive(Debug, Clone)]
pub enum TileMessage {
    /// Raw network packet
    Packet {
        data: Vec<u8>,
        from: std::net::SocketAddr,
        received_at: Instant,
    },

    /// Transaction to verify/execute
    Transaction {
        tx: Transaction,
        signature_verified: bool,
        priority: u8,
    },

    /// Verified transaction batch
    VerifiedBatch {
        transactions: Vec<Transaction>,
        slot: u64,
    },

    /// Block to shred
    Block {
        block: Block,
        slot: u64,
    },

    /// Shred to propagate
    Shred {
        data: Vec<u8>,
        slot: u64,
        index: u32,
    },

    /// PoH tick
    PohTick {
        hash: Hash,
        slot: u64,
        tick: u64,
    },

    /// Control message
    Control(ControlMessage),

    /// Shutdown signal
    Shutdown,
}

/// Control messages for tile management
#[derive(Debug, Clone)]
pub enum ControlMessage {
    /// Pause processing
    Pause,
    /// Resume processing
    Resume,
    /// Report stats
    ReportStats,
    /// Update configuration
    UpdateConfig(TileConfig),
}

// =============================================================================
// TILE STATISTICS
// =============================================================================

/// Statistics for a tile
#[derive(Debug, Clone, Default)]
pub struct TileStats {
    /// Messages received
    pub messages_received: u64,
    /// Messages processed
    pub messages_processed: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages dropped (queue full)
    pub messages_dropped: u64,
    /// Processing errors
    pub errors: u64,
    /// Average processing time (microseconds)
    pub avg_processing_time_us: u64,
    /// Max processing time (microseconds)
    pub max_processing_time_us: u64,
    /// Queue depth (current)
    pub input_queue_depth: usize,
    /// Output queue depth (current)
    pub output_queue_depth: usize,
    /// Uptime in seconds
    pub uptime_secs: u64,
}

// =============================================================================
// TILE TRAIT
// =============================================================================

/// Trait that all tiles must implement
pub trait Tile: Send + Sync {
    /// Get tile ID
    fn id(&self) -> TileId;

    /// Get tile name
    fn name(&self) -> &str;

    /// Process a single message
    fn process(&self, message: TileMessage) -> Result<Vec<TileMessage>, TileError>;

    /// Called when tile starts
    fn on_start(&self) {}

    /// Called when tile stops
    fn on_stop(&self) {}

    /// Get current statistics
    fn stats(&self) -> TileStats;
}

// =============================================================================
// NETWORK TILE
// =============================================================================

/// Network I/O tile - receives and sends packets
pub struct NetTile {
    config: TileConfig,
    stats: RwLock<TileStats>,
    running: AtomicBool,
    start_time: RwLock<Option<Instant>>,
}

impl NetTile {
    pub fn new(config: TileConfig) -> Self {
        Self {
            config,
            stats: RwLock::new(TileStats::default()),
            running: AtomicBool::new(false),
            start_time: RwLock::new(None),
        }
    }
}

impl Tile for NetTile {
    fn id(&self) -> TileId {
        TileId::NET_TILE
    }

    fn name(&self) -> &str {
        "net"
    }

    fn process(&self, message: TileMessage) -> Result<Vec<TileMessage>, TileError> {
        let start = Instant::now();
        let mut stats = self.stats.write();
        stats.messages_received += 1;

        let result = match message {
            TileMessage::Packet { data, from, received_at } => {
                // Parse packet and forward to appropriate tile
                if data.len() < 4 {
                    return Err(TileError::InvalidMessage("packet too small".into()));
                }

                // Check packet type (first 4 bytes as magic)
                let packet_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

                match packet_type {
                    0x5458 => {
                        // TX packet - forward to sig verify
                        stats.messages_processed += 1;
                        stats.messages_sent += 1;
                        Ok(vec![TileMessage::Transaction {
                            tx: Transaction::default(), // Would deserialize from data
                            signature_verified: false,
                            priority: 0,
                        }])
                    }
                    0x5348 => {
                        // Shred packet - forward directly
                        stats.messages_processed += 1;
                        stats.messages_sent += 1;
                        Ok(vec![TileMessage::Shred {
                            data: data[4..].to_vec(),
                            slot: 0,
                            index: 0,
                        }])
                    }
                    _ => {
                        // Unknown packet type
                        Err(TileError::InvalidMessage("unknown packet type".into()))
                    }
                }
            }
            TileMessage::Shred { data, slot, index } => {
                // Outgoing shred - would send to network
                stats.messages_processed += 1;
                stats.messages_sent += 1;
                Ok(vec![]) // Consumed, sent to network
            }
            TileMessage::Control(ctrl) => {
                match ctrl {
                    ControlMessage::Pause => self.running.store(false, Ordering::SeqCst),
                    ControlMessage::Resume => self.running.store(true, Ordering::SeqCst),
                    _ => {}
                }
                Ok(vec![])
            }
            TileMessage::Shutdown => {
                self.running.store(false, Ordering::SeqCst);
                Ok(vec![])
            }
            _ => Err(TileError::InvalidMessage("unexpected message type".into())),
        };

        let elapsed = start.elapsed().as_micros() as u64;
        stats.avg_processing_time_us = (stats.avg_processing_time_us + elapsed) / 2;
        stats.max_processing_time_us = stats.max_processing_time_us.max(elapsed);

        result
    }

    fn on_start(&self) {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.write() = Some(Instant::now());
    }

    fn on_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> TileStats {
        let mut stats = self.stats.read().clone();
        if let Some(start) = *self.start_time.read() {
            stats.uptime_secs = start.elapsed().as_secs();
        }
        stats
    }
}

// =============================================================================
// SIGNATURE VERIFICATION TILE
// =============================================================================

/// Signature verification tile - verifies transaction signatures in parallel
pub struct SigVerifyTile {
    config: TileConfig,
    stats: RwLock<TileStats>,
    running: AtomicBool,
    start_time: RwLock<Option<Instant>>,
    /// Batch size for parallel verification
    batch_size: usize,
    /// Pending transactions for batching
    pending: Mutex<Vec<Transaction>>,
}

impl SigVerifyTile {
    pub fn new(config: TileConfig) -> Self {
        Self {
            config,
            stats: RwLock::new(TileStats::default()),
            running: AtomicBool::new(false),
            start_time: RwLock::new(None),
            batch_size: 64,
            pending: Mutex::new(Vec::with_capacity(64)),
        }
    }

    /// Verify a batch of transactions in parallel
    fn verify_batch(&self, transactions: &[Transaction]) -> Vec<bool> {
        // In production, use rayon for parallel verification
        transactions.iter()
            .map(|tx| tx.verify_signatures())
            .collect()
    }
}

impl Tile for SigVerifyTile {
    fn id(&self) -> TileId {
        TileId::SIG_VERIFY_TILE
    }

    fn name(&self) -> &str {
        "sigverify"
    }

    fn process(&self, message: TileMessage) -> Result<Vec<TileMessage>, TileError> {
        let start = Instant::now();
        let mut stats = self.stats.write();
        stats.messages_received += 1;

        let result = match message {
            TileMessage::Transaction { tx, signature_verified, priority } => {
                if signature_verified {
                    // Already verified, pass through
                    stats.messages_processed += 1;
                    stats.messages_sent += 1;
                    return Ok(vec![TileMessage::Transaction {
                        tx,
                        signature_verified: true,
                        priority,
                    }]);
                }

                // Add to batch
                let mut pending = self.pending.lock();
                pending.push(tx);

                // If batch is full, verify all
                if pending.len() >= self.batch_size {
                    let batch: Vec<Transaction> = pending.drain(..).collect();
                    drop(pending);

                    let results = self.verify_batch(&batch);

                    let mut output = Vec::new();
                    for (tx, valid) in batch.into_iter().zip(results) {
                        if valid {
                            stats.messages_processed += 1;
                            stats.messages_sent += 1;
                            output.push(TileMessage::Transaction {
                                tx,
                                signature_verified: true,
                                priority,
                            });
                        } else {
                            stats.errors += 1;
                        }
                    }

                    Ok(output)
                } else {
                    // Not enough for batch yet
                    Ok(vec![])
                }
            }
            TileMessage::Control(ctrl) => {
                match ctrl {
                    ControlMessage::Pause => self.running.store(false, Ordering::SeqCst),
                    ControlMessage::Resume => self.running.store(true, Ordering::SeqCst),
                    _ => {}
                }
                Ok(vec![])
            }
            TileMessage::Shutdown => {
                self.running.store(false, Ordering::SeqCst);

                // Flush pending
                let mut pending = self.pending.lock();
                if !pending.is_empty() {
                    let batch: Vec<Transaction> = pending.drain(..).collect();
                    let results = self.verify_batch(&batch);
                    let mut output = Vec::new();
                    for (tx, valid) in batch.into_iter().zip(results) {
                        if valid {
                            output.push(TileMessage::Transaction {
                                tx,
                                signature_verified: true,
                                priority: 0,
                            });
                        }
                    }
                    return Ok(output);
                }

                Ok(vec![])
            }
            _ => Err(TileError::InvalidMessage("unexpected message type".into())),
        };

        let elapsed = start.elapsed().as_micros() as u64;
        stats.avg_processing_time_us = (stats.avg_processing_time_us + elapsed) / 2;
        stats.max_processing_time_us = stats.max_processing_time_us.max(elapsed);

        result
    }

    fn on_start(&self) {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.write() = Some(Instant::now());
    }

    fn on_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> TileStats {
        let mut stats = self.stats.read().clone();
        if let Some(start) = *self.start_time.read() {
            stats.uptime_secs = start.elapsed().as_secs();
        }
        stats.input_queue_depth = self.pending.lock().len();
        stats
    }
}

// =============================================================================
// BANK TILE
// =============================================================================

/// Bank tile - executes transactions and updates state
pub struct BankTile {
    config: TileConfig,
    stats: RwLock<TileStats>,
    running: AtomicBool,
    start_time: RwLock<Option<Instant>>,
    /// Current slot
    current_slot: AtomicU64,
    /// Transactions in current slot
    slot_transactions: Mutex<Vec<Transaction>>,
}

impl BankTile {
    pub fn new(config: TileConfig) -> Self {
        Self {
            config,
            stats: RwLock::new(TileStats::default()),
            running: AtomicBool::new(false),
            start_time: RwLock::new(None),
            current_slot: AtomicU64::new(0),
            slot_transactions: Mutex::new(Vec::new()),
        }
    }

    pub fn set_slot(&self, slot: u64) {
        self.current_slot.store(slot, Ordering::SeqCst);
    }
}

impl Tile for BankTile {
    fn id(&self) -> TileId {
        TileId::BANK_TILE
    }

    fn name(&self) -> &str {
        "bank"
    }

    fn process(&self, message: TileMessage) -> Result<Vec<TileMessage>, TileError> {
        let start = Instant::now();
        let mut stats = self.stats.write();
        stats.messages_received += 1;

        let result = match message {
            TileMessage::Transaction { tx, signature_verified, priority } => {
                if !signature_verified {
                    return Err(TileError::InvalidMessage("signature not verified".into()));
                }

                // Execute transaction (simplified)
                let mut slot_txs = self.slot_transactions.lock();
                slot_txs.push(tx);
                stats.messages_processed += 1;

                Ok(vec![])
            }
            TileMessage::VerifiedBatch { transactions, slot } => {
                // Execute batch
                let mut slot_txs = self.slot_transactions.lock();
                for tx in transactions {
                    slot_txs.push(tx);
                }
                stats.messages_processed += slot_txs.len() as u64;
                Ok(vec![])
            }
            TileMessage::PohTick { slot, tick, .. } => {
                // End of slot - build block
                if tick == crate::TICKS_PER_SLOT - 1 {
                    let mut slot_txs = self.slot_transactions.lock();
                    let transactions: Vec<Transaction> = slot_txs.drain(..).collect();

                    if !transactions.is_empty() {
                        stats.messages_sent += 1;
                        return Ok(vec![TileMessage::Block {
                            block: Block {
                                header: crate::core::BlockHeader {
                                    slot,
                                    previous_hash: Hash::zero(),
                                    transactions_root: Hash::zero(),
                                    state_root: Hash::zero(),
                                    poh_hash: Hash::zero(),
                                    tick_count: tick,
                                    leader: Pubkey::default(),
                                    timestamp: 0,
                                    height: slot,
                                },
                                transactions,
                            },
                            slot,
                        }]);
                    }
                }
                Ok(vec![])
            }
            TileMessage::Control(ctrl) => {
                match ctrl {
                    ControlMessage::Pause => self.running.store(false, Ordering::SeqCst),
                    ControlMessage::Resume => self.running.store(true, Ordering::SeqCst),
                    _ => {}
                }
                Ok(vec![])
            }
            TileMessage::Shutdown => {
                self.running.store(false, Ordering::SeqCst);
                Ok(vec![])
            }
            _ => Err(TileError::InvalidMessage("unexpected message type".into())),
        };

        let elapsed = start.elapsed().as_micros() as u64;
        stats.avg_processing_time_us = (stats.avg_processing_time_us + elapsed) / 2;
        stats.max_processing_time_us = stats.max_processing_time_us.max(elapsed);

        result
    }

    fn on_start(&self) {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.write() = Some(Instant::now());
    }

    fn on_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> TileStats {
        let mut stats = self.stats.read().clone();
        if let Some(start) = *self.start_time.read() {
            stats.uptime_secs = start.elapsed().as_secs();
        }
        stats.input_queue_depth = self.slot_transactions.lock().len();
        stats
    }
}

// =============================================================================
// POH TILE
// =============================================================================

/// PoH tile - generates Proof of History ticks
pub struct PohTile {
    config: TileConfig,
    stats: RwLock<TileStats>,
    running: AtomicBool,
    start_time: RwLock<Option<Instant>>,
    /// Current hash
    current_hash: RwLock<Hash>,
    /// Current slot
    current_slot: AtomicU64,
    /// Current tick within slot
    current_tick: AtomicU64,
    /// Hashes per tick
    hashes_per_tick: u64,
}

impl PohTile {
    pub fn new(config: TileConfig, hashes_per_tick: u64) -> Self {
        Self {
            config,
            stats: RwLock::new(TileStats::default()),
            running: AtomicBool::new(false),
            start_time: RwLock::new(None),
            current_hash: RwLock::new(Hash::zero()),
            current_slot: AtomicU64::new(0),
            current_tick: AtomicU64::new(0),
            hashes_per_tick,
        }
    }

    /// Generate next tick
    fn generate_tick(&self) -> Hash {
        let mut hash = *self.current_hash.read();
        for _ in 0..self.hashes_per_tick {
            hash = Hash::hash(hash.as_bytes());
        }
        *self.current_hash.write() = hash;
        hash
    }
}

impl Tile for PohTile {
    fn id(&self) -> TileId {
        TileId::POH_TILE
    }

    fn name(&self) -> &str {
        "poh"
    }

    fn process(&self, message: TileMessage) -> Result<Vec<TileMessage>, TileError> {
        let start = Instant::now();
        let mut stats = self.stats.write();
        stats.messages_received += 1;

        let result = match message {
            TileMessage::Transaction { tx, .. } => {
                // Mix transaction into PoH
                let tx_hash = tx.hash();
                let current = *self.current_hash.read();
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(current.as_bytes());
                combined.extend_from_slice(tx_hash.as_bytes());
                let new_hash = Hash::hash(&combined);
                *self.current_hash.write() = new_hash;
                stats.messages_processed += 1;
                Ok(vec![])
            }
            TileMessage::Control(ControlMessage::Resume) => {
                // Generate tick on resume (timer tick)
                let tick = self.current_tick.fetch_add(1, Ordering::SeqCst);
                let slot = self.current_slot.load(Ordering::SeqCst);

                let hash = self.generate_tick();
                stats.messages_processed += 1;
                stats.messages_sent += 1;

                // Check if end of slot
                if tick >= crate::TICKS_PER_SLOT - 1 {
                    self.current_tick.store(0, Ordering::SeqCst);
                    self.current_slot.fetch_add(1, Ordering::SeqCst);
                }

                Ok(vec![TileMessage::PohTick {
                    hash,
                    slot,
                    tick,
                }])
            }
            TileMessage::Control(ctrl) => {
                match ctrl {
                    ControlMessage::Pause => self.running.store(false, Ordering::SeqCst),
                    _ => {}
                }
                Ok(vec![])
            }
            TileMessage::Shutdown => {
                self.running.store(false, Ordering::SeqCst);
                Ok(vec![])
            }
            _ => Ok(vec![]),
        };

        let elapsed = start.elapsed().as_micros() as u64;
        stats.avg_processing_time_us = (stats.avg_processing_time_us + elapsed) / 2;
        stats.max_processing_time_us = stats.max_processing_time_us.max(elapsed);

        result
    }

    fn on_start(&self) {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.write() = Some(Instant::now());
    }

    fn on_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> TileStats {
        let mut stats = self.stats.read().clone();
        if let Some(start) = *self.start_time.read() {
            stats.uptime_secs = start.elapsed().as_secs();
        }
        stats
    }
}

// =============================================================================
// SHRED TILE
// =============================================================================

/// Shred tile - creates shreds from blocks using FEC
pub struct ShredTile {
    config: TileConfig,
    stats: RwLock<TileStats>,
    running: AtomicBool,
    start_time: RwLock<Option<Instant>>,
}

impl ShredTile {
    pub fn new(config: TileConfig) -> Self {
        Self {
            config,
            stats: RwLock::new(TileStats::default()),
            running: AtomicBool::new(false),
            start_time: RwLock::new(None),
        }
    }
}

impl Tile for ShredTile {
    fn id(&self) -> TileId {
        TileId::SHRED_TILE
    }

    fn name(&self) -> &str {
        "shred"
    }

    fn process(&self, message: TileMessage) -> Result<Vec<TileMessage>, TileError> {
        let start = Instant::now();
        let mut stats = self.stats.write();
        stats.messages_received += 1;

        let result = match message {
            TileMessage::Block { block, slot } => {
                // Serialize block
                let data = bincode::serialize(&block)
                    .map_err(|e| TileError::ProcessingError(e.to_string()))?;

                // Create shreds using FEC encoder
                let fec_config = crate::fec::FecConfig::default();
                let encoder = crate::fec::FecEncoder::new(fec_config);
                let block_hash = Hash::hash(&data);

                let shreds = encoder.encode(slot, block_hash, &data)
                    .map_err(|e| TileError::ProcessingError(e.to_string()))?;

                stats.messages_processed += 1;
                stats.messages_sent += shreds.len() as u64;

                // Convert to tile messages
                let messages: Vec<TileMessage> = shreds.into_iter()
                    .map(|shred| TileMessage::Shred {
                        data: shred.payload,
                        slot,
                        index: shred.header.index,
                    })
                    .collect();

                Ok(messages)
            }
            TileMessage::Control(ctrl) => {
                match ctrl {
                    ControlMessage::Pause => self.running.store(false, Ordering::SeqCst),
                    ControlMessage::Resume => self.running.store(true, Ordering::SeqCst),
                    _ => {}
                }
                Ok(vec![])
            }
            TileMessage::Shutdown => {
                self.running.store(false, Ordering::SeqCst);
                Ok(vec![])
            }
            _ => Err(TileError::InvalidMessage("unexpected message type".into())),
        };

        let elapsed = start.elapsed().as_micros() as u64;
        stats.avg_processing_time_us = (stats.avg_processing_time_us + elapsed) / 2;
        stats.max_processing_time_us = stats.max_processing_time_us.max(elapsed);

        result
    }

    fn on_start(&self) {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.write() = Some(Instant::now());
    }

    fn on_stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn stats(&self) -> TileStats {
        let mut stats = self.stats.read().clone();
        if let Some(start) = *self.start_time.read() {
            stats.uptime_secs = start.elapsed().as_secs();
        }
        stats
    }
}

// =============================================================================
// TILE MANAGER
// =============================================================================

/// Manages all tiles and their communication
pub struct TileManager {
    /// Registered tiles
    tiles: RwLock<HashMap<TileId, Arc<dyn Tile>>>,
    /// Message channels between tiles
    channels: RwLock<HashMap<(TileId, TileId), (Sender<TileMessage>, Receiver<TileMessage>)>>,
    /// Running threads
    threads: Mutex<Vec<JoinHandle<()>>>,
    /// Global running flag
    running: AtomicBool,
}

impl TileManager {
    pub fn new() -> Self {
        Self {
            tiles: RwLock::new(HashMap::new()),
            channels: RwLock::new(HashMap::new()),
            threads: Mutex::new(Vec::new()),
            running: AtomicBool::new(false),
        }
    }

    /// Register a tile
    pub fn register(&self, tile: Arc<dyn Tile>) {
        let id = tile.id();
        self.tiles.write().insert(id, tile);
    }

    /// Create a channel between two tiles
    pub fn connect(&self, from: TileId, to: TileId, capacity: usize) {
        let (tx, rx) = bounded(capacity);
        self.channels.write().insert((from, to), (tx, rx));
    }

    /// Send a message to a tile
    pub fn send(&self, from: TileId, to: TileId, message: TileMessage) -> Result<(), TileError> {
        let channels = self.channels.read();
        if let Some((tx, _)) = channels.get(&(from, to)) {
            tx.try_send(message).map_err(|e| match e {
                TrySendError::Full(_) => TileError::QueueFull,
                TrySendError::Disconnected(_) => TileError::Disconnected,
            })
        } else {
            Err(TileError::NoChannel)
        }
    }

    /// Start all tiles
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);

        let tiles = self.tiles.read();
        for (id, tile) in tiles.iter() {
            tile.on_start();
        }
    }

    /// Stop all tiles
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);

        // Send shutdown to all tiles
        let tiles = self.tiles.read();
        for (_, tile) in tiles.iter() {
            tile.on_stop();
        }

        // Wait for threads
        let mut threads = self.threads.lock();
        for thread in threads.drain(..) {
            let _ = thread.join();
        }
    }

    /// Get stats for all tiles
    pub fn all_stats(&self) -> HashMap<TileId, TileStats> {
        let tiles = self.tiles.read();
        tiles.iter()
            .map(|(id, tile)| (*id, tile.stats()))
            .collect()
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Default for TileManager {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// ERROR TYPES
// =============================================================================

#[derive(Debug, Clone, thiserror::Error)]
pub enum TileError {
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    #[error("Processing error: {0}")]
    ProcessingError(String),

    #[error("Queue full")]
    QueueFull,

    #[error("Tile disconnected")]
    Disconnected,

    #[error("No channel between tiles")]
    NoChannel,

    #[error("Tile not found")]
    TileNotFound,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tile_config() {
        let config = TileConfig {
            id: TileId::NET_TILE,
            name: "network".to_string(),
            ..Default::default()
        };

        assert_eq!(config.id, TileId::NET_TILE);
        assert_eq!(config.input_queue_size, 10_000);
    }

    #[test]
    fn test_net_tile() {
        let config = TileConfig {
            id: TileId::NET_TILE,
            name: "net".to_string(),
            ..Default::default()
        };

        let tile = NetTile::new(config);
        tile.on_start();

        // Process a packet
        let packet = TileMessage::Packet {
            data: vec![0x54, 0x58, 0, 0, 1, 2, 3, 4],
            from: "127.0.0.1:8000".parse().unwrap(),
            received_at: Instant::now(),
        };

        let result = tile.process(packet);
        assert!(result.is_ok());

        let stats = tile.stats();
        assert_eq!(stats.messages_received, 1);
    }

    #[test]
    fn test_tile_manager() {
        let manager = TileManager::new();

        let net_config = TileConfig {
            id: TileId::NET_TILE,
            name: "net".to_string(),
            ..Default::default()
        };
        let net_tile = Arc::new(NetTile::new(net_config));

        let sig_config = TileConfig {
            id: TileId::SIG_VERIFY_TILE,
            name: "sigverify".to_string(),
            ..Default::default()
        };
        let sig_tile = Arc::new(SigVerifyTile::new(sig_config));

        manager.register(net_tile);
        manager.register(sig_tile);
        manager.connect(TileId::NET_TILE, TileId::SIG_VERIFY_TILE, 1000);

        manager.start();
        assert!(manager.is_running());

        manager.stop();
        assert!(!manager.is_running());
    }
}
