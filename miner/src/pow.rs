use anyhow::{bail, Result};
use bitcoin::blockdata::block::Header as BlockHeader;
use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, Target, Work};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Mining statistics
#[derive(Debug, Clone)]
pub struct MiningStats {
    pub hash_rate: f64,
    pub hashes_computed: u64,
    pub time_elapsed: Duration,
    pub nonce_start: u32,
    pub nonce_end: u32,
}

/// Proof-of-work miner
pub struct ProofOfWorkMiner {
    num_threads: usize,
    stop_flag: Arc<AtomicBool>,
    best_nonce: Arc<AtomicU32>,
}

impl ProofOfWorkMiner {
    pub fn new(num_threads: usize) -> Self {
        Self {
            num_threads,
            stop_flag: Arc::new(AtomicBool::new(false)),
            best_nonce: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Mine a block header to find a valid nonce
    pub fn mine_block_header(
        &self,
        mut header: BlockHeader,
        target: Target,
        timeout: Option<Duration>,
    ) -> Result<(BlockHeader, MiningStats)> {
        info!(
            "Starting proof-of-work mining with {} threads",
            self.num_threads
        );
        debug!("Target: {:?}", target);

        let start_time = Instant::now();
        let timeout_duration = timeout.unwrap_or(Duration::from_secs(600)); // 10 minutes default

        // Fast path for very easy targets (regtest/testing)
        if target == Target::MAX || target.to_compact_lossy().to_consensus() == 0x207fffff {
            // For regtest or minimum difficulty, just use a simple nonce
            header.nonce = 1;
            let hash = header.block_hash();

            // Check if it's valid (it usually is for MAX target)
            if Self::check_proof_of_work(&hash, target) {
                let stats = MiningStats {
                    hash_rate: 1.0,
                    hashes_computed: 1,
                    time_elapsed: Duration::from_millis(1),
                    nonce_start: 0,
                    nonce_end: 1,
                };
                return Ok((header, stats));
            }

            // Try a few more nonces quickly
            for nonce in 2..1000 {
                header.nonce = nonce;
                let hash = header.block_hash();
                if Self::check_proof_of_work(&hash, target) {
                    let elapsed = start_time.elapsed();
                    let stats = MiningStats {
                        hash_rate: nonce as f64 / elapsed.as_secs_f64().max(0.001),
                        hashes_computed: nonce as u64,
                        time_elapsed: elapsed,
                        nonce_start: 0,
                        nonce_end: nonce,
                    };
                    return Ok((header, stats));
                }
            }
        }

        // Reset stop flag and best nonce
        self.stop_flag.store(false, Ordering::Relaxed);
        self.best_nonce.store(0, Ordering::Relaxed);

        // Divide nonce space among threads
        let nonce_range = u32::MAX / self.num_threads as u32;
        let mut handles = Vec::new();

        for thread_id in 0..self.num_threads {
            let nonce_start = thread_id as u32 * nonce_range;
            let nonce_end = if thread_id == self.num_threads - 1 {
                u32::MAX
            } else {
                (thread_id + 1) as u32 * nonce_range - 1
            };

            let mut thread_header = header;
            let thread_target = target;
            let stop_flag = Arc::clone(&self.stop_flag);
            let best_nonce = Arc::clone(&self.best_nonce);

            let handle = std::thread::spawn(move || {
                Self::mine_thread(
                    thread_id,
                    &mut thread_header,
                    thread_target,
                    nonce_start,
                    nonce_end,
                    stop_flag,
                    best_nonce,
                )
            });

            handles.push(handle);
        }

        // Wait for timeout or solution
        let mut found = false;
        let mut total_hashes = 0u64;

        while !found && start_time.elapsed() < timeout_duration {
            std::thread::sleep(Duration::from_millis(100));

            // Check if any thread found a solution
            let nonce = self.best_nonce.load(Ordering::Relaxed);
            if nonce != 0 || self.stop_flag.load(Ordering::Relaxed) {
                found = true;
                header.nonce = nonce;
            }
        }

        // Stop all threads
        self.stop_flag.store(true, Ordering::Relaxed);

        // Wait for threads to finish
        for handle in handles {
            if let Ok(hashes) = handle.join() {
                total_hashes += hashes;
            }
        }

        if !found {
            bail!("Mining timeout - no valid nonce found");
        }

        let elapsed = start_time.elapsed();
        let stats = MiningStats {
            hash_rate: total_hashes as f64 / elapsed.as_secs_f64(),
            hashes_computed: total_hashes,
            time_elapsed: elapsed,
            nonce_start: 0,
            nonce_end: header.nonce,
        };

        info!(
            "Mining completed in {:.2}s, {} hashes, {:.2} MH/s",
            elapsed.as_secs_f64(),
            total_hashes,
            stats.hash_rate / 1_000_000.0
        );

        Ok((header, stats))
    }

    /// Mining thread worker
    fn mine_thread(
        thread_id: usize,
        header: &mut BlockHeader,
        target: Target,
        nonce_start: u32,
        nonce_end: u32,
        stop_flag: Arc<AtomicBool>,
        best_nonce: Arc<AtomicU32>,
    ) -> u64 {
        debug!(
            "Thread {} mining nonces {} to {}",
            thread_id, nonce_start, nonce_end
        );

        let mut nonce = nonce_start;
        let mut hashes = 0u64;

        while nonce <= nonce_end && !stop_flag.load(Ordering::Relaxed) {
            header.nonce = nonce;
            let hash = header.block_hash();
            hashes += 1;

            // Check if we found a valid solution
            if Self::check_proof_of_work(&hash, target) {
                info!("Thread {} found valid nonce: {}", thread_id, nonce);
                best_nonce.store(nonce, Ordering::Relaxed);
                stop_flag.store(true, Ordering::Relaxed);
                break;
            }

            // Check every 10000 hashes if we should stop
            if hashes.is_multiple_of(10000) && stop_flag.load(Ordering::Relaxed) {
                break;
            }

            nonce = nonce.wrapping_add(1);
        }

        debug!("Thread {} computed {} hashes", thread_id, hashes);
        hashes
    }

    /// Check if a block hash meets the target difficulty
    pub fn check_proof_of_work(hash: &BlockHash, target: Target) -> bool {
        // Convert hash to Target for comparison
        let hash_bytes = hash.to_byte_array();
        let hash_target = Target::from_le_bytes(hash_bytes);
        hash_target <= target
    }

    /// Validate a block's proof of work
    pub fn validate_block_pow(block: &Block) -> Result<bool> {
        let target = block.header.target();
        let hash = block.header.block_hash();

        if !Self::check_proof_of_work(&hash, target) {
            warn!("Block {} has invalid proof of work", hash);
            return Ok(false);
        }

        Ok(true)
    }

    /// Calculate the work represented by a block
    pub fn calculate_work(header: &BlockHeader) -> Work {
        header.work()
    }

    /// Stop mining
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

/// ASIC miner simulator (for testing)
pub struct AsicMiner {
    hash_rate: f64, // Hashes per second
}

impl AsicMiner {
    pub fn new(hash_rate: f64) -> Self {
        Self { hash_rate }
    }

    /// Simulate ASIC mining
    pub fn mine(
        &self,
        mut header: BlockHeader,
        target: Target,
        duration: Duration,
    ) -> Result<Option<BlockHeader>> {
        let total_hashes = (self.hash_rate * duration.as_secs_f64()) as u64;
        info!(
            "ASIC mining simulation: {} hashes over {:?}",
            total_hashes, duration
        );

        // Probability of finding a block
        let difficulty = Self::target_to_difficulty(target);
        let probability = total_hashes as f64 / difficulty;

        // Simulate finding a nonce (simplified)
        if rand::random::<f64>() < probability {
            header.nonce = rand::random();

            // Actually mine to find valid nonce (for correctness)
            let miner = ProofOfWorkMiner::new(1);
            let (mined_header, _) =
                miner.mine_block_header(header, target, Some(Duration::from_secs(1)))?;

            info!("ASIC miner found block!");
            Ok(Some(mined_header))
        } else {
            Ok(None)
        }
    }

    fn target_to_difficulty(target: Target) -> f64 {
        // Proper difficulty calculation: max_target / current_target
        let max_target = Target::MAX_ATTAINABLE_MAINNET;
        let max_bytes = max_target.to_le_bytes();
        let target_bytes = target.to_le_bytes();

        // Convert both to floating point for division
        // This is sufficient for simulation purposes
        let mut max_val = 0.0_f64;
        let mut target_val = 0.0_f64;

        // Build up the values from bytes (little-endian)
        for i in 0..32 {
            if i < max_bytes.len() {
                max_val += (max_bytes[i] as f64) * 256.0_f64.powi(i as i32);
            }
            if i < target_bytes.len() {
                target_val += (target_bytes[i] as f64) * 256.0_f64.powi(i as i32);
            }
        }

        if target_val > 0.0 {
            max_val / target_val
        } else {
            1.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_of_work_validation() {
        // Create a test header with easy target
        let header = BlockHeader {
            version: bitcoin::blockdata::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff), // Easy difficulty
            nonce: 0,
        };

        let target = header.target();

        // Mine with 1 thread
        let miner = ProofOfWorkMiner::new(1);
        let result = miner.mine_block_header(header, target, Some(Duration::from_secs(10)));

        assert!(result.is_ok());
        let (mined_header, stats) = result.unwrap();
        assert!(ProofOfWorkMiner::check_proof_of_work(
            &mined_header.block_hash(),
            target
        ));
        assert!(stats.hashes_computed > 0);
    }

    #[test]
    fn test_multi_threaded_mining() {
        let header = BlockHeader {
            version: bitcoin::blockdata::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff), // Easy difficulty
            nonce: 0,
        };

        let target = header.target();

        // Mine with 4 threads
        let miner = ProofOfWorkMiner::new(4);
        let result = miner.mine_block_header(header, target, Some(Duration::from_secs(10)));

        assert!(result.is_ok());
        let (mined_header, stats) = result.unwrap();
        assert!(ProofOfWorkMiner::check_proof_of_work(
            &mined_header.block_hash(),
            target
        ));
        println!("Hash rate: {:.2} MH/s", stats.hash_rate / 1_000_000.0);
    }
}
