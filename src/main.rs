//! Celereum Node - High-performance blockchain node
//!
//! Usage:
//!   celereum-node --help

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use std::collections::HashMap;
use celereum::{
    consensus::{ProofOfHistory, Validator, LeaderSchedule},
    consensus::validator::ValidatorInfo as ConsensusValidatorInfo,
    consensus::tower_bft::VoteAggregator,
    crypto::Keypair,
    core::Vote,
    storage::{Storage, ValidatorInfo},
    rpc::RpcServer,
    network::{NetworkNode, NetworkConfig, GossipConfig},
    runtime::TransactionExecutor,
    CELEREUM_VERSION, TICKS_PER_SLOT, SLOTS_PER_EPOCH, CELERS_PER_CEL, TARGET_TPS,
};
use clap::{Parser, Subcommand};
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "celereum-node")]
#[command(author = "Celereum Team")]
#[command(version = CELEREUM_VERSION)]
#[command(about = "Celereum blockchain node", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a validator node
    Validator {
        /// Path to keypair file
        #[arg(short, long)]
        keypair: Option<String>,

        /// RPC port
        #[arg(short, long, default_value = "8899")]
        rpc_port: u16,

        /// Gossip port
        #[arg(short, long, default_value = "8001")]
        gossip_port: u16,

        /// Data directory
        #[arg(short, long, default_value = "./data")]
        data_dir: String,

        /// Bootstrap peers (comma-separated)
        #[arg(short, long)]
        bootstrap: Option<String>,

        /// Enable leader mode (produces blocks)
        #[arg(long)]
        leader: bool,
    },

    /// Start an RPC-only node (no validation)
    Rpc {
        /// RPC port
        #[arg(short, long, default_value = "8899")]
        rpc_port: u16,

        /// Data directory
        #[arg(short, long, default_value = "./data")]
        data_dir: String,
    },

    /// Generate a new keypair
    Keygen {
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,

        /// Generate vanity address with prefix
        #[arg(long)]
        vanity: Option<String>,
    },

    /// Show node info
    Info,

    /// Benchmark PoH performance
    Benchmark {
        /// Duration in seconds
        #[arg(short, long, default_value = "5")]
        duration: u64,
    },

    /// Create genesis block
    Genesis {
        /// Output directory
        #[arg(short, long, default_value = "./genesis")]
        output: String,

        /// Initial supply in CEL
        #[arg(long, default_value = "1000000000")]
        supply: u64,

        /// Number of validators
        #[arg(long, default_value = "2")]
        validators: u32,
    },

    /// Get account balance
    Balance {
        /// Account address
        address: String,

        /// RPC URL
        #[arg(long, default_value = "http://localhost:8899")]
        rpc: String,
    },

    /// Request airdrop (testnet)
    Airdrop {
        /// Amount in CEL
        #[arg(short, long, default_value = "1.0")]
        amount: f64,

        /// Target address (defaults to new keypair)
        #[arg(short, long)]
        to: Option<String>,

        /// RPC URL
        #[arg(long, default_value = "http://localhost:8899")]
        rpc: String,
    },
}

fn main() {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let cli = Cli::parse();

    match cli.command {
        Commands::Validator { keypair, rpc_port, gossip_port, data_dir, bootstrap, leader } => {
            run_validator(keypair, rpc_port, gossip_port, data_dir, bootstrap, leader);
        }
        Commands::Rpc { rpc_port, data_dir } => {
            run_rpc_node(rpc_port, data_dir);
        }
        Commands::Keygen { output, vanity } => {
            generate_keypair(output, vanity);
        }
        Commands::Info => {
            show_info();
        }
        Commands::Benchmark { duration } => {
            run_benchmark(duration);
        }
        Commands::Genesis { output, supply, validators } => {
            create_genesis(output, supply, validators);
        }
        Commands::Balance { address, rpc } => {
            get_balance(address, rpc);
        }
        Commands::Airdrop { amount, to, rpc } => {
            request_airdrop(amount, to, rpc);
        }
    }
}

fn run_validator(
    keypair_path: Option<String>,
    rpc_port: u16,
    gossip_port: u16,
    data_dir: String,
    bootstrap: Option<String>,
    leader: bool,
) {
    info!("Starting Celereum validator node...");
    info!("Version: {}", CELEREUM_VERSION);
    info!("RPC port: {}", rpc_port);
    info!("Gossip port: {}", gossip_port);
    info!("Data directory: {}", data_dir);

    // Create tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create runtime");

    rt.block_on(async {
        // Create data directory first (needed for keypair storage)
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            error!("Failed to create data directory: {}", e);
            return;
        }

        // Load or create keypair (auto-saves to data_dir/validator-keypair.json)
        let keypair = load_or_create_keypair(keypair_path.as_deref(), &data_dir);

        info!("Validator identity: {}", keypair.pubkey());

        // Initialize storage
        let storage = Arc::new(Storage::new_persistent(&format!("{}/db", data_dir)).expect("Failed to create storage"));
        info!("Storage initialized");

        // Parse bootstrap peers
        let bootstrap_peers: Vec<SocketAddr> = bootstrap
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        if !bootstrap_peers.is_empty() {
            info!("Bootstrap peers: {:?}", bootstrap_peers);
        }

        // Start RPC server
        let rpc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), rpc_port);
        let mut rpc_server = RpcServer::new(rpc_addr, storage.clone());
        if let Err(e) = rpc_server.start().await {
            error!("Failed to start RPC server: {}", e);
            return;
        }
        info!("RPC server running at http://{}", rpc_addr);

        // Start network node
        let gossip_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), gossip_port);
        let network_config = NetworkConfig {
            gossip_addr,
            bootstrap_peers,
            gossip_config: GossipConfig::default(),
        };
        let mut network = NetworkNode::new(keypair.clone(), storage.clone(), network_config);

        // Take receivers before starting
        let _tx_receiver = network.take_tx_receiver();
        let block_receiver = network.take_block_receiver();

        if let Err(e) = network.start().await {
            error!("Failed to start network: {}", e);
            return;
        }
        info!("Network node running on {}", gossip_addr);

        // Create validator
        let mut validator = Validator::new(keypair.clone(), 1000, 10000);
        validator.set_leader(leader);

        // Register validator in storage so it shows up in RPC
        let validator_address = keypair.address();
        let validator_info = ValidatorInfo {
            pubkey: validator_address.clone(),
            name: format!("Validator-{}", &validator_address.to_base58()[..8]),
            stake: 1_000_000_000_000, // 1000 CEL stake
            commission: 5,
            active: true,
            skip_rate: 0.0,
            blocks_produced: 0,
            uptime: 100.0,
        };
        storage.add_validator(validator_info.clone());
        info!("Validator registered in storage");

        // Create leader schedule for multi-validator support
        let consensus_validator_info = ConsensusValidatorInfo {
            identity: validator_address.clone(),
            vote_account: validator.vote_pubkey(),
            stake: 1_000_000_000_000,
            last_vote: None,
            root_slot: None,
            commission: 5,
            activated: true,
        };

        // Get all registered validators and create leader schedule
        let all_validators: Vec<ConsensusValidatorInfo> = storage.get_validators()
            .iter()
            .map(|v| ConsensusValidatorInfo {
                identity: v.pubkey.clone(),
                vote_account: v.pubkey.clone(), // Use same key for simplicity
                stake: v.stake,
                last_vote: None,
                root_slot: None,
                commission: v.commission,
                activated: v.active,
            })
            .collect();

        // Create initial leader schedule (will be updated as more validators join)
        let leader_schedule = if all_validators.is_empty() {
            LeaderSchedule::new(&[consensus_validator_info], 0, SLOTS_PER_EPOCH)
        } else {
            LeaderSchedule::new(&all_validators, 0, SLOTS_PER_EPOCH)
        };
        validator.set_leader_schedule(leader_schedule.clone());
        info!("Leader schedule created for {} validators", storage.get_validator_count());

        if leader {
            info!("Running in LEADER mode - will produce blocks");
        } else {
            info!("Running in FOLLOWER mode - will validate and sync blocks");
        }

        // Transaction executor
        let executor = TransactionExecutor::new();

        // Create vote aggregator for PoS consensus
        let mut stakes: HashMap<celereum::crypto::Pubkey, u64> = HashMap::new();
        for v in storage.get_validators() {
            stakes.insert(v.pubkey.clone(), v.stake);
        }
        let mut vote_aggregator = VoteAggregator::new(stakes);
        info!("Vote aggregator initialized with {} validators", storage.get_validator_count());

        // Track finalized slots
        let mut last_finalized_slot: Option<u64> = None;
        let mut votes_sent = 0u64;

        // Main loop
        info!("Validator is running... Press Ctrl+C to stop");

        let _running = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let mut slot_timer = tokio::time::interval(Duration::from_millis(200)); // 5 slots/sec
        let mut block_count = 0u64;
        let mut tx_count = 0u64;
        let mut received_blocks = 0u64;
        let mut current_slot = 0u64;

        // Get block receiver for followers
        let mut block_rx = block_receiver;

        loop {
            tokio::select! {
                _ = slot_timer.tick() => {
                    // Check if we're the leader for this slot using the leader schedule
                    let is_slot_leader = if leader {
                        // In leader mode, check schedule
                        leader_schedule.is_leader(current_slot, &validator_address)
                    } else {
                        false // Followers don't produce blocks
                    };

                    // Update validator's leader status based on schedule
                    validator.set_leader(is_slot_leader);

                    if is_slot_leader {
                        // Leader for this slot: produce block
                        let pending_txs = storage.get_pending_transactions();

                        // Debug log
                        if block_count == 0 || block_count % 100 == 0 {
                            info!("Slot {}: Leader for this slot, pending_txs={}", current_slot, pending_txs.len());
                        }

                        // Execute transactions
                        if !pending_txs.is_empty() {
                            let results = executor.execute_batch(pending_txs.clone());
                            tx_count += results.iter().filter(|r| r.success).count() as u64;
                        }

                        // Produce block
                        if let Some(block) = validator.produce_block(pending_txs) {
                            storage.add_block(block.clone());
                            block_count += 1;

                            // Update validator stats
                            storage.increment_validator_blocks(&keypair.address());

                            // Create and record our own vote for this block (PoS consensus)
                            let vote = Vote::new(
                                block.header.slot,
                                block.hash(),
                                validator_info.stake,
                                &keypair,
                            );
                            if let Ok(()) = vote_aggregator.add_vote(&vote) {
                                votes_sent += 1;
                            }

                            // Check for finality (supermajority)
                            if vote_aggregator.has_supermajority(block.header.slot) {
                                if last_finalized_slot.map(|s| block.header.slot > s).unwrap_or(true) {
                                    last_finalized_slot = Some(block.header.slot);
                                    if block_count % 50 == 0 {
                                        info!("Slot {} finalized with supermajority!", block.header.slot);
                                    }
                                }
                            }

                            if block_count % 10 == 0 {
                                info!(
                                    "Block {} | Hash: {}.. | TXs: {} | Finalized: {:?}",
                                    block.header.slot,
                                    &block.hash().to_base58()[..8],
                                    tx_count,
                                    last_finalized_slot
                                );
                            }

                            // Broadcast block to network
                            network.broadcast_block(&block).await;
                        }
                    } else if leader {
                        // Not our slot, but we're in leader mode - just increment slot
                        current_slot += 1;
                    }

                    // Increment slot counter
                    if is_slot_leader {
                        current_slot = validator.slot;
                    }
                }
                // Receive blocks from network (all validators receive blocks)
                Some(block) = async {
                    if let Some(ref mut rx) = block_rx {
                        rx.recv().await
                    } else {
                        None
                    }
                }, if block_rx.is_some() => {
                    // Validate the received block
                    if block.verify() {
                        // Check if block is from valid leader
                        let expected_leader = leader_schedule.get_leader(block.header.slot);
                        let is_valid_leader = expected_leader
                            .map(|l| l == block.header.leader)
                            .unwrap_or(false);

                        if is_valid_leader || !leader {
                            // Accept block from valid leader or if we're a follower
                            storage.add_block(block.clone());
                            received_blocks += 1;
                            current_slot = block.header.slot + 1;

                            // Vote for this block (PoS consensus)
                            let vote = Vote::new(
                                block.header.slot,
                                block.hash(),
                                validator_info.stake,
                                &keypair,
                            );
                            if let Ok(()) = vote_aggregator.add_vote(&vote) {
                                votes_sent += 1;
                            }

                            // Check for finality
                            if vote_aggregator.has_supermajority(block.header.slot) {
                                if last_finalized_slot.map(|s| block.header.slot > s).unwrap_or(true) {
                                    last_finalized_slot = Some(block.header.slot);
                                }
                            }

                            if received_blocks % 10 == 0 {
                                info!(
                                    "Received block {} | Hash: {}.. | From: {}.. | Finalized: {:?}",
                                    block.header.slot,
                                    &block.hash().to_base58()[..8],
                                    &block.header.leader.to_base58()[..8],
                                    last_finalized_slot
                                );
                            }
                        } else {
                            warn!(
                                "Block {} rejected: wrong leader. Expected: {:?}, Got: {}",
                                block.header.slot,
                                expected_leader.map(|l| l.to_base58()),
                                block.header.leader.to_base58()
                            );
                        }
                    } else {
                        warn!("Received invalid block at slot {}", block.header.slot);
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Shutting down...");
                    break;
                }
            }
        }

        if leader {
            info!("Validator stopped. Produced {} blocks, {} transactions", block_count, tx_count);
        } else {
            info!("Validator stopped. Received {} blocks", received_blocks);
        }
        network.stop();
        rpc_server.stop().await;
    });
}

fn run_rpc_node(rpc_port: u16, data_dir: String) {
    info!("Starting Celereum RPC node...");
    info!("Version: {}", CELEREUM_VERSION);
    info!("RPC port: {}", rpc_port);
    info!("Data directory: {}", data_dir);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create runtime");

    rt.block_on(async {
        // Create data directory
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            error!("Failed to create data directory: {}", e);
            return;
        }

        let storage = Arc::new(Storage::new_persistent(&format!("{}/db", data_dir)).expect("Failed to create storage"));

        let rpc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), rpc_port);
        let mut rpc_server = RpcServer::new(rpc_addr, storage);

        if let Err(e) = rpc_server.start().await {
            error!("Failed to start RPC server: {}", e);
            return;
        }

        info!("RPC server running at http://{}", rpc_addr);
        info!("Press Ctrl+C to stop");

        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down...");
        rpc_server.stop().await;
    });
}

fn generate_keypair(output: Option<String>, vanity: Option<String>) {
    let keypair = if let Some(prefix) = vanity {
        println!("Searching for vanity address with prefix '{}'...", prefix);
        let prefix_lower = prefix.to_lowercase();
        let mut attempts = 0u64;
        loop {
            let kp = Keypair::generate();
            let pubkey = kp.pubkey().to_base58().to_lowercase();
            attempts += 1;

            if pubkey.starts_with(&prefix_lower) {
                println!("Found after {} attempts!", attempts);
                break kp;
            }

            if attempts % 100000 == 0 {
                println!("  {} attempts...", attempts);
            }
        }
    } else {
        Keypair::generate()
    };

    println!();
    println!("+------------------------------------------------------------------+");
    println!("|                    NEW CELEREUM KEYPAIR                          |");
    println!("+------------------------------------------------------------------+");
    println!("| Public Key (Address):                                            |");
    println!("|   {}", keypair.pubkey());
    println!("+------------------------------------------------------------------+");
    println!("| Secret Key (KEEP PRIVATE!):                                      |");
    println!("|   {}", hex::encode(keypair.secret()));
    println!("+------------------------------------------------------------------+");

    if let Some(path) = output {
        // Save to file
        let data = serde_json::json!({
            "pubkey": keypair.pubkey().to_base58(),
            "secret": hex::encode(keypair.secret()),
        });
        if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(&data).unwrap()) {
            eprintln!("Failed to save keypair: {}", e);
        } else {
            println!("\nKeypair saved to: {}", path);
        }
    }
}

fn show_info() {
    println!();
    println!("   ____     _                              ");
    println!("  / ___|___| | ___ _ __ ___ _   _ _ __ ___  ");
    println!(" | |   / _ \\ |/ _ \\ '__/ _ \\ | | | '_ ` _ \\ ");
    println!(" | |__|  __/ |  __/ | |  __/ |_| | | | | | |");
    println!("  \\____\\___|_|\\___|_|  \\___|\\__,_|_| |_| |_|");
    println!();
    println!("Swift Beyond Measure - High-Performance Blockchain");
    println!("==================================================");
    println!();
    println!("Version:          {}", CELEREUM_VERSION);
    println!("Ticks per slot:   {}", TICKS_PER_SLOT);
    println!("Slots per epoch:  {}", SLOTS_PER_EPOCH);
    println!("Celers/CEL:       {}", CELERS_PER_CEL);
    println!("Target TPS:       {}", TARGET_TPS);
    println!();
    println!("Features:");
    println!("  [x] Proof of History (PoH) - Verifiable time");
    println!("  [x] Tower BFT - Optimized PBFT consensus");
    println!("  [x] Sealevel - Parallel transaction execution");
    println!("  [x] Gulf Stream - Mempool-less forwarding");
    println!("  [x] Turbine - Block propagation");
    println!("  [x] Cloudbreak - Horizontally-scaled accounts DB");
    println!();
    println!("Commands:");
    println!("  validator  - Start a validator node");
    println!("  rpc        - Start an RPC-only node");
    println!("  keygen     - Generate a new keypair");
    println!("  genesis    - Create genesis block");
    println!("  benchmark  - Benchmark PoH performance");
    println!("  balance    - Check account balance");
    println!("  airdrop    - Request testnet tokens");
    println!();
}

fn run_benchmark(duration: u64) {
    use std::time::Duration;

    println!();
    println!("+---------------------------------------------------------------+");
    println!("|              CELEREUM POV BENCHMARK                           |");
    println!("+---------------------------------------------------------------+");
    println!();
    println!("Running benchmark for {} seconds...", duration);
    println!();

    let hashes_per_second = ProofOfHistory::benchmark(Duration::from_secs(duration));

    let hashes_per_tick = 12_500u64;
    let tick_time_ms = (hashes_per_tick as f64 / hashes_per_second as f64) * 1000.0;
    let slot_time_ms = tick_time_ms * TICKS_PER_SLOT as f64;
    let theoretical_tps = hashes_per_second / 1000;

    println!("Results:");
    println!("  - Hashes/second:    {}", format_number(hashes_per_second));
    println!("  - Tick time:        {:.2} ms", tick_time_ms);
    println!("  - Slot time:        {:.2} ms", slot_time_ms);
    println!("  - Theoretical TPS:  {}", format_number(theoretical_tps));
    println!();

    if hashes_per_second > 1_000_000 {
        println!("[OK] Excellent! Your hardware can support high-performance validation.");
    } else if hashes_per_second > 500_000 {
        println!("[OK] Good. Your hardware meets minimum requirements.");
    } else {
        println!("[WARN] Your hardware may struggle with validation.");
    }
    println!();
}

fn create_genesis(output: String, _supply: u64, validator_count: u32) {
    use celereum::core::block::{GenesisConfig, VestingSchedule};

    println!();
    println!("+---------------------------------------------------------------+");
    println!("|              CELEREUM GENESIS CREATION                        |");
    println!("|              Tokenomics: 210,000,000 CEL                       |");
    println!("+---------------------------------------------------------------+");
    println!();

    // Total supply: 210 million CEL
    let total_supply = 210_000_000u64;
    let total_celers = total_supply * CELERS_PER_CEL;

    // Slot calculations (1 slot = ~320ms, ~270K slots/day)
    let slots_per_day: u64 = 270_000;
    let slots_per_year: u64 = slots_per_day * 365;

    // ============================================
    // TOKENOMICS DISTRIBUTION (210M CEL)
    // ============================================
    // Public Sale:     40% = 84,000,000 CEL - No lock
    // Team & Advisors: 15% = 31,500,000 CEL - 4 year vest, 1 year cliff
    // Development:     20% = 42,000,000 CEL - 5 year linear
    // Ecosystem:       15% = 31,500,000 CEL - 10 year staking rewards
    // Treasury:        10% = 21,000,000 CEL - Governance controlled

    // Generate allocation keypairs
    let public_sale_kp = Keypair::generate();
    let team_kp = Keypair::generate();
    let development_kp = Keypair::generate();
    let ecosystem_kp = Keypair::generate();
    let treasury_kp = Keypair::generate();

    // Calculate allocations
    let public_sale_amount = 84_000_000u64 * CELERS_PER_CEL;  // 40%
    let team_amount = 31_500_000u64 * CELERS_PER_CEL;         // 15%
    let development_amount = 42_000_000u64 * CELERS_PER_CEL;  // 20%
    let ecosystem_amount = 31_500_000u64 * CELERS_PER_CEL;    // 15%
    let treasury_amount = 21_000_000u64 * CELERS_PER_CEL;     // 10%

    // Vesting schedules
    let vesting_schedules = vec![
        VestingSchedule {
            address: team_kp.address(),
            total_amount: team_amount,
            initial_unlock: 0, // No initial unlock
            cliff_slots: slots_per_year, // 1 year cliff
            vesting_duration_slots: slots_per_year * 4, // 4 years total
            category: "Team & Advisors".to_string(),
        },
        VestingSchedule {
            address: development_kp.address(),
            total_amount: development_amount,
            initial_unlock: development_amount / 10, // 10% initial
            cliff_slots: 0, // No cliff
            vesting_duration_slots: slots_per_year * 5, // 5 years linear
            category: "Development".to_string(),
        },
        VestingSchedule {
            address: ecosystem_kp.address(),
            total_amount: ecosystem_amount,
            initial_unlock: 0,
            cliff_slots: 0,
            vesting_duration_slots: slots_per_year * 10, // 10 year emission
            category: "Ecosystem/Staking Rewards".to_string(),
        },
    ];

    // Generate validators
    let mut validators = Vec::new();
    let stake_per_validator = treasury_amount / (validator_count as u64 * 2);

    for i in 0..validator_count {
        let validator = Keypair::generate();
        let vote_account = Keypair::generate();

        validators.push(celereum::core::block::ValidatorConfig {
            address: validator.address(),
            vote_account: vote_account.address(),
            stake: stake_per_validator,
        });

        println!("Validator {}:", i + 1);
        println!("  Identity:     {}", validator.address());
        println!("  Vote Account: {}", vote_account.address());
        println!("  Stake:        {} CEL", stake_per_validator / CELERS_PER_CEL);
        println!("  Secret:       {}", hex::encode(validator.secret()));
        println!();
    }

    // Genesis accounts (liquid + vesting total)
    let config = GenesisConfig {
        creation_time: chrono::Utc::now().timestamp(),
        accounts: vec![
            (public_sale_kp.address(), public_sale_amount),  // Fully liquid
            (team_kp.address(), team_amount),                 // Vested
            (development_kp.address(), development_amount),   // Vested
            (ecosystem_kp.address(), ecosystem_amount),       // Vested
            (treasury_kp.address(), treasury_amount),         // Governance
        ],
        validators: validators.clone(),
        cluster_name: "celereum-mainnet".to_string(),
        ticks_per_slot: TICKS_PER_SLOT,
        slots_per_epoch: SLOTS_PER_EPOCH,
    };

    let genesis_block = config.create_genesis_block();

    println!("================================================================");
    println!("                    TOKENOMICS SUMMARY");
    println!("================================================================");
    println!();
    println!("Total Supply: {} CEL", total_supply);
    println!();
    println!("Allocation                 | Amount          | Vesting");
    println!("---------------------------|-----------------|------------------");
    println!("Public Sale (40%)          | 84,000,000 CEL  | No lock");
    println!("Team & Advisors (15%)      | 31,500,000 CEL  | 4yr, 1yr cliff");
    println!("Development (20%)          | 42,000,000 CEL  | 5yr linear (10% TGE)");
    println!("Ecosystem/Rewards (15%)    | 31,500,000 CEL  | 10yr emission");
    println!("Treasury (10%)             | 21,000,000 CEL  | Governance");
    println!();
    println!("================================================================");
    println!("                    GENESIS BLOCK");
    println!("================================================================");
    println!("Hash:    {}", genesis_block.hash());
    println!("Cluster: {}", config.cluster_name);
    println!();

    // Create output directory
    if let Err(e) = std::fs::create_dir_all(&output) {
        eprintln!("Failed to create directory: {}", e);
        return;
    }

    // Save comprehensive genesis config
    let genesis_json = serde_json::json!({
        "cluster_name": config.cluster_name,
        "creation_time": config.creation_time,
        "genesis_hash": genesis_block.hash().to_base58(),
        "total_supply": total_supply,
        "total_supply_celers": total_celers,

        "tokenomics": {
            "public_sale": {
                "address": public_sale_kp.address().to_base58(),
                "secret": hex::encode(public_sale_kp.secret()),
                "amount_cel": 84_000_000u64,
                "amount_celers": public_sale_amount,
                "percentage": 40,
                "vesting": "None - Fully liquid"
            },
            "team": {
                "address": team_kp.address().to_base58(),
                "secret": hex::encode(team_kp.secret()),
                "amount_cel": 31_500_000u64,
                "amount_celers": team_amount,
                "percentage": 15,
                "vesting": "4 years, 1 year cliff",
                "cliff_slots": slots_per_year,
                "vesting_duration_slots": slots_per_year * 4
            },
            "development": {
                "address": development_kp.address().to_base58(),
                "secret": hex::encode(development_kp.secret()),
                "amount_cel": 42_000_000u64,
                "amount_celers": development_amount,
                "percentage": 20,
                "vesting": "5 years linear, 10% TGE",
                "initial_unlock_celers": development_amount / 10,
                "vesting_duration_slots": slots_per_year * 5
            },
            "ecosystem": {
                "address": ecosystem_kp.address().to_base58(),
                "secret": hex::encode(ecosystem_kp.secret()),
                "amount_cel": 31_500_000u64,
                "amount_celers": ecosystem_amount,
                "percentage": 15,
                "vesting": "10 year emission for staking rewards",
                "vesting_duration_slots": slots_per_year * 10
            },
            "treasury": {
                "address": treasury_kp.address().to_base58(),
                "secret": hex::encode(treasury_kp.secret()),
                "amount_cel": 21_000_000u64,
                "amount_celers": treasury_amount,
                "percentage": 10,
                "vesting": "Governance controlled"
            }
        },

        "validators": validators.iter().enumerate().map(|(i, v)| {
            serde_json::json!({
                "index": i,
                "address": v.address.to_base58(),
                "vote_account": v.vote_account.to_base58(),
                "stake_celers": v.stake,
                "stake_cel": v.stake / CELERS_PER_CEL,
            })
        }).collect::<Vec<_>>(),

        "vesting_schedules": vesting_schedules.iter().map(|v| {
            serde_json::json!({
                "category": v.category,
                "address": v.address.to_base58(),
                "total_amount": v.total_amount,
                "initial_unlock": v.initial_unlock,
                "cliff_slots": v.cliff_slots,
                "vesting_duration_slots": v.vesting_duration_slots,
            })
        }).collect::<Vec<_>>(),

        "network_params": {
            "ticks_per_slot": TICKS_PER_SLOT,
            "slots_per_epoch": SLOTS_PER_EPOCH,
            "slots_per_day": slots_per_day,
            "slots_per_year": slots_per_year,
            "celers_per_cel": CELERS_PER_CEL,
        }
    });

    let genesis_path = format!("{}/genesis.json", output);
    if let Err(e) = std::fs::write(&genesis_path, serde_json::to_string_pretty(&genesis_json).unwrap()) {
        eprintln!("Failed to save genesis: {}", e);
    } else {
        println!("Genesis saved to: {}", genesis_path);
    }

    // Print account addresses for easy reference
    println!();
    println!("================================================================");
    println!("                    ACCOUNT ADDRESSES");
    println!("================================================================");
    println!("Public Sale: {}", public_sale_kp.address());
    println!("Team:        {}", team_kp.address());
    println!("Development: {}", development_kp.address());
    println!("Ecosystem:   {}", ecosystem_kp.address());
    println!("Treasury:    {}", treasury_kp.address());
    println!();
    println!("IMPORTANT: Backup genesis.json - it contains all private keys!");
    println!();
}

fn get_balance(address: String, rpc: String) {
    println!();
    println!("Checking balance for: {}", address);
    println!("RPC endpoint: {}", rpc);
    println!();

    // Simple HTTP request using std library
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create runtime");

    rt.block_on(async {
        let request_body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["{}"]}}"#,
            address
        );

        match simple_http_post(&rpc, &request_body).await {
            Ok(response) => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                    if let Some(result) = json.get("result") {
                        let celers = result.as_u64().unwrap_or(0);
                        let cel = celers as f64 / CELERS_PER_CEL as f64;
                        println!("Balance: {} CEL ({} celers)", cel, celers);
                    } else if let Some(error) = json.get("error") {
                        println!("Error: {}", error);
                    }
                } else {
                    println!("Failed to parse response: {}", response);
                }
            }
            Err(e) => {
                println!("Failed to connect to RPC: {}", e);
                println!("Make sure the node is running.");
            }
        }
    });
}

fn request_airdrop(amount: f64, to: Option<String>, rpc: String) {
    let target = to.unwrap_or_else(|| {
        let kp = Keypair::generate();
        println!("Generated new keypair for airdrop:");
        println!("  Address: {}", kp.pubkey());
        println!("  Secret:  {}", hex::encode(kp.secret()));
        println!();
        kp.pubkey().to_base58()
    });

    let celers = (amount * CELERS_PER_CEL as f64) as u64;

    println!("Requesting airdrop of {} CEL to {}", amount, target);
    println!("RPC endpoint: {}", rpc);
    println!();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create runtime");

    rt.block_on(async {
        let request_body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"requestAirdrop","params":["{}",{}]}}"#,
            target, celers
        );

        match simple_http_post(&rpc, &request_body).await {
            Ok(response) => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                    if let Some(result) = json.get("result") {
                        println!("[OK] Airdrop successful!");
                        println!("  Signature: {}", result);
                    } else if let Some(error) = json.get("error") {
                        println!("[FAIL] Airdrop failed: {}", error);
                    }
                } else {
                    println!("Failed to parse response");
                }
            }
            Err(e) => {
                println!("Failed to connect to RPC: {}", e);
                println!("Make sure the node is running.");
            }
        }
    });
}

/// Simple HTTP POST using tokio TCP
async fn simple_http_post(url: &str, body: &str) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    // Parse URL (simple parsing for localhost)
    let url = url.trim_start_matches("http://");
    let (host_port, _path) = url.split_once('/').unwrap_or((url, ""));
    let (host, port) = host_port.split_once(':').unwrap_or((host_port, "80"));
    let port: u16 = port.parse().unwrap_or(80);

    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr).await?;

    // Build HTTP request
    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        host_port,
        body.len(),
        body
    );

    stream.write_all(request.as_bytes()).await?;

    // Read response
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let response_str = String::from_utf8_lossy(&response);

    // Extract body from HTTP response
    if let Some(pos) = response_str.find("\r\n\r\n") {
        Ok(response_str[pos + 4..].to_string())
    } else {
        Ok(response_str.to_string())
    }
}

fn load_keypair(path: &str) -> Result<Keypair, Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&data)?;

    let secret_hex = json["secret"].as_str().ok_or("Missing secret key")?;
    let secret_bytes = hex::decode(secret_hex)?;

    if secret_bytes.len() != 32 {
        return Err("Invalid secret key length (expected 32-byte seed)".into());
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret_bytes);

    // Use from_seed for deterministic keypair generation from 32-byte seed
    Ok(Keypair::from_seed(&seed))
}

fn save_keypair(keypair: &Keypair, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    // Get the seed bytes from the keypair (32 bytes)
    let seed = keypair.secret();
    let secret_hex = hex::encode(seed);
    let pubkey = keypair.pubkey().to_base58();

    let json = serde_json::json!({
        "pubkey": pubkey,
        "secret": secret_hex,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "version": 1
    });

    let mut file = std::fs::File::create(path)?;
    file.write_all(serde_json::to_string_pretty(&json)?.as_bytes())?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Load or create keypair with auto-save to data directory
fn load_or_create_keypair(keypair_path: Option<&str>, data_dir: &str) -> Keypair {
    // First, try explicit keypair path if provided
    if let Some(path) = keypair_path {
        match load_keypair(path) {
            Ok(kp) => {
                info!("Loaded keypair from: {}", path);
                return kp;
            }
            Err(e) => {
                warn!("Failed to load keypair from {}: {}", path, e);
            }
        }
    }

    // Try default keypair location in data directory
    let default_path = format!("{}/validator-keypair.json", data_dir);
    if std::path::Path::new(&default_path).exists() {
        match load_keypair(&default_path) {
            Ok(kp) => {
                info!("Loaded existing keypair from: {}", default_path);
                return kp;
            }
            Err(e) => {
                warn!("Failed to load keypair from {}: {}", default_path, e);
            }
        }
    }

    // Generate new keypair and save it
    info!("Generating new keypair...");
    let keypair = Keypair::generate();

    // Save to data directory
    match save_keypair(&keypair, &default_path) {
        Ok(_) => {
            info!("Saved new keypair to: {}", default_path);
            info!("IMPORTANT: Back up this file! It contains your validator identity.");
        }
        Err(e) => {
            error!("Failed to save keypair: {}. Keypair will not persist!", e);
        }
    }

    keypair
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}
