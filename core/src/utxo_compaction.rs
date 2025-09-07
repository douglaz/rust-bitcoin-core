use anyhow::{Result, Context, bail};
use bitcoin::{OutPoint, TxOut, Txid, ScriptBuf};
use std::collections::{HashMap, HashSet, BTreeMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error, trace};

/// UTXO set compaction for efficient storage and retrieval
pub struct UtxoCompactor {
    /// Database reference
    database: Arc<crate::database::CoreDatabase>,
    
    /// Compaction statistics
    stats: Arc<RwLock<CompactionStats>>,
    
    /// Compaction configuration
    config: CompactionConfig,
}

/// Compaction configuration
#[derive(Debug, Clone)]
pub struct CompactionConfig {
    /// Minimum UTXO count to trigger compaction
    pub min_utxos: usize,
    
    /// Target database size in bytes
    pub target_size: u64,
    
    /// Enable automatic compaction
    pub auto_compact: bool,
    
    /// Compaction interval
    pub compact_interval: Duration,
    
    /// Batch size for processing
    pub batch_size: usize,
    
    /// Cache spent outputs for faster validation
    pub cache_spent: bool,
    
    /// Maximum spent cache size
    pub max_spent_cache: usize,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            min_utxos: 1_000_000,
            target_size: 5_000_000_000, // 5 GB
            auto_compact: true,
            compact_interval: Duration::from_secs(3600), // 1 hour
            batch_size: 10_000,
            cache_spent: true,
            max_spent_cache: 100_000,
        }
    }
}

/// Compaction statistics
#[derive(Debug, Default)]
pub struct CompactionStats {
    pub last_compaction: Option<Instant>,
    pub total_compactions: u64,
    pub utxos_processed: u64,
    pub bytes_saved: u64,
    pub current_utxo_count: usize,
    pub current_db_size: u64,
    pub spent_cache_hits: u64,
    pub spent_cache_misses: u64,
}

/// UTXO entry with metadata for compaction
#[derive(Debug, Clone)]
pub struct CompactUtxo {
    pub outpoint: OutPoint,
    pub output: TxOut,
    pub height: u32,
    pub is_coinbase: bool,
    pub last_accessed: Option<Instant>,
}

/// Spent output cache entry
#[derive(Debug, Clone)]
struct SpentEntry {
    pub height: u32,
    pub spent_at: Instant,
}

impl UtxoCompactor {
    /// Create new UTXO compactor
    pub fn new(database: Arc<crate::database::CoreDatabase>) -> Self {
        Self::with_config(database, CompactionConfig::default())
    }
    
    /// Create with custom configuration
    pub fn with_config(database: Arc<crate::database::CoreDatabase>, config: CompactionConfig) -> Self {
        Self {
            database,
            stats: Arc::new(RwLock::new(CompactionStats::default())),
            config,
        }
    }
    
    /// Perform UTXO set compaction
    pub async fn compact(&self) -> Result<CompactionResult> {
        info!("Starting UTXO set compaction");
        let start_time = Instant::now();
        
        // Get current statistics
        let initial_stats = self.analyze_utxo_set().await?;
        
        // Check if compaction is needed
        if !self.should_compact(&initial_stats).await {
            debug!("Compaction not needed");
            return Ok(CompactionResult {
                duration: start_time.elapsed(),
                utxos_processed: 0,
                bytes_saved: 0,
                errors: 0,
            });
        }
        
        // Perform compaction steps
        let mut result = CompactionResult {
            duration: Duration::from_secs(0),
            utxos_processed: 0,
            bytes_saved: 0,
            errors: 0,
        };
        
        // Step 1: Remove dust outputs
        result.add(self.remove_dust_outputs().await?);
        
        // Step 2: Consolidate fragmented entries
        result.add(self.consolidate_fragments().await?);
        
        // Step 3: Optimize storage format
        result.add(self.optimize_storage().await?);
        
        // Step 4: Clean up spent cache
        result.add(self.cleanup_spent_cache().await?);
        
        // Step 5: Rebuild indexes
        result.add(self.rebuild_indexes().await?);
        
        // Update statistics
        let final_stats = self.analyze_utxo_set().await?;
        
        result.duration = start_time.elapsed();
        result.bytes_saved = initial_stats.total_size.saturating_sub(final_stats.total_size);
        
        // Update compaction stats
        {
            let mut stats = self.stats.write().await;
            stats.last_compaction = Some(Instant::now());
            stats.total_compactions += 1;
            stats.utxos_processed += result.utxos_processed;
            stats.bytes_saved += result.bytes_saved;
            stats.current_utxo_count = final_stats.utxo_count;
            stats.current_db_size = final_stats.total_size;
        }
        
        info!(
            "Compaction completed: {} UTXOs processed, {} bytes saved in {:?}",
            result.utxos_processed, result.bytes_saved, result.duration
        );
        
        Ok(result)
    }
    
    /// Check if compaction should be performed
    async fn should_compact(&self, stats: &UtxoSetStats) -> bool {
        if !self.config.auto_compact {
            return false;
        }
        
        // Check UTXO count threshold
        if stats.utxo_count >= self.config.min_utxos {
            return true;
        }
        
        // Check database size
        if stats.total_size >= self.config.target_size {
            return true;
        }
        
        // Check time since last compaction
        if let Some(last) = self.stats.read().await.last_compaction {
            if last.elapsed() >= self.config.compact_interval {
                return true;
            }
        }
        
        false
    }
    
    /// Analyze current UTXO set
    async fn analyze_utxo_set(&self) -> Result<UtxoSetStats> {
        debug!("Analyzing UTXO set");
        
        let mut stats = UtxoSetStats::default();
        
        // Get UTXO count and size from database
        stats.utxo_count = self.database.count_utxos()?;
        stats.total_size = self.database.get_database_size()?;
        
        // Analyze UTXO distribution
        let utxos = self.database.get_all_utxos_paginated(0, self.config.batch_size)?;
        
        for utxo in utxos {
            // Categorize by value
            let value = utxo.output.value.to_sat();
            if value < 546 { // Dust threshold
                stats.dust_outputs += 1;
            } else if value < 10_000 {
                stats.small_outputs += 1;
            } else if value < 1_000_000 {
                stats.medium_outputs += 1;
            } else {
                stats.large_outputs += 1;
            }
            
            // Track script types
            if utxo.output.script_pubkey.is_p2pkh() {
                stats.p2pkh_outputs += 1;
            } else if utxo.output.script_pubkey.is_p2sh() {
                stats.p2sh_outputs += 1;
            } else if utxo.output.script_pubkey.is_p2wpkh() {
                stats.p2wpkh_outputs += 1;
            } else if utxo.output.script_pubkey.is_p2wsh() {
                stats.p2wsh_outputs += 1;
            }
        }
        
        Ok(stats)
    }
    
    /// Remove dust outputs that are unlikely to be spent
    async fn remove_dust_outputs(&self) -> Result<CompactionResult> {
        debug!("Removing dust outputs");
        
        let mut result = CompactionResult::default();
        let mut removed_count = 0;
        
        // Get all UTXOs in batches
        let mut offset = 0;
        loop {
            let utxos = self.database.get_all_utxos_paginated(offset, self.config.batch_size)?;
            if utxos.is_empty() {
                break;
            }
            
            let mut to_remove = Vec::new();
            
            for utxo in &utxos {
                // Check if dust (less than relay fee)
                if utxo.output.value.to_sat() < 546 {
                    // Only remove if old enough (e.g., > 1 year)
                    if utxo.height < self.database.get_current_height()?.saturating_sub(52560) {
                        to_remove.push(utxo.outpoint);
                        removed_count += 1;
                    }
                }
            }
            
            // Remove dust UTXOs
            if !to_remove.is_empty() {
                let mut batch = self.database.begin_batch()?;
                for outpoint in to_remove {
                    self.database.remove_utxo(&mut batch, &outpoint)?;
                }
                self.database.commit_batch(batch)?;
            }
            
            result.utxos_processed += utxos.len() as u64;
            offset += self.config.batch_size;
        }
        
        debug!("Removed {} dust outputs", removed_count);
        Ok(result)
    }
    
    /// Consolidate fragmented database entries
    async fn consolidate_fragments(&self) -> Result<CompactionResult> {
        debug!("Consolidating fragmented entries");
        
        let mut result = CompactionResult::default();
        
        // Group UTXOs by transaction
        let mut tx_groups: HashMap<Txid, Vec<CompactUtxo>> = HashMap::new();
        
        let mut offset = 0;
        loop {
            let utxos = self.database.get_all_utxos_paginated(offset, self.config.batch_size)?;
            if utxos.is_empty() {
                break;
            }
            
            for utxo in utxos {
                tx_groups.entry(utxo.outpoint.txid)
                    .or_insert_with(Vec::new)
                    .push(CompactUtxo {
                        outpoint: utxo.outpoint,
                        output: utxo.output,
                        height: utxo.height,
                        is_coinbase: utxo.is_coinbase,
                        last_accessed: None,
                    });
            }
            
            offset += self.config.batch_size;
        }
        
        // Rewrite grouped entries for better locality
        let mut batch = self.database.begin_batch()?;
        let mut consolidated = 0;
        
        for (txid, mut utxos) in tx_groups {
            if utxos.len() > 1 {
                // Sort by output index
                utxos.sort_by_key(|u| u.outpoint.vout);
                
                // Store consecutively
                for utxo in utxos {
                    self.database.add_utxo(
                        &mut batch,
                        &utxo.outpoint,
                        &utxo.output,
                    )?;
                    consolidated += 1;
                }
            }
        }
        
        self.database.commit_batch(batch)?;
        
        result.utxos_processed = consolidated;
        debug!("Consolidated {} UTXO entries", consolidated);
        
        Ok(result)
    }
    
    /// Optimize storage format
    async fn optimize_storage(&self) -> Result<CompactionResult> {
        debug!("Optimizing storage format");
        
        let mut result = CompactionResult::default();
        
        // Compress script pubkeys
        let compressed = self.compress_scripts().await?;
        result.add(compressed);
        
        // Deduplicate common patterns
        let deduped = self.deduplicate_patterns().await?;
        result.add(deduped);
        
        Ok(result)
    }
    
    /// Compress script pubkeys
    async fn compress_scripts(&self) -> Result<CompactionResult> {
        let mut result = CompactionResult::default();
        
        // Build script template cache
        let mut templates: HashMap<ScriptTemplate, u32> = HashMap::new();
        let mut template_id = 0u32;
        
        let mut offset = 0;
        loop {
            let utxos = self.database.get_all_utxos_paginated(offset, self.config.batch_size)?;
            if utxos.is_empty() {
                break;
            }
            
            for utxo in utxos {
                let template = ScriptTemplate::from_script(&utxo.output.script_pubkey);
                templates.entry(template).or_insert_with(|| {
                    let id = template_id;
                    template_id += 1;
                    id
                });
                result.utxos_processed += 1;
            }
            
            offset += self.config.batch_size;
        }
        
        debug!("Found {} unique script templates", templates.len());
        
        // Store template mapping
        self.database.store_script_templates(&templates)?;
        
        Ok(result)
    }
    
    /// Deduplicate common patterns
    async fn deduplicate_patterns(&self) -> Result<CompactionResult> {
        let mut result = CompactionResult::default();
        
        // Find duplicate amounts
        let mut amount_counts: BTreeMap<u64, usize> = BTreeMap::new();
        
        let mut offset = 0;
        loop {
            let utxos = self.database.get_all_utxos_paginated(offset, self.config.batch_size)?;
            if utxos.is_empty() {
                break;
            }
            
            for utxo in utxos {
                *amount_counts.entry(utxo.output.value.to_sat()).or_insert(0) += 1;
            }
            
            offset += self.config.batch_size;
        }
        
        // Find common amounts (appearing > 100 times)
        let common_amounts: Vec<u64> = amount_counts
            .into_iter()
            .filter(|(_, count)| *count > 100)
            .map(|(amount, _)| amount)
            .collect();
        
        debug!("Found {} common output amounts", common_amounts.len());
        
        // Store common amounts for efficient encoding
        self.database.store_common_amounts(&common_amounts)?;
        
        Ok(result)
    }
    
    /// Clean up spent output cache
    async fn cleanup_spent_cache(&self) -> Result<CompactionResult> {
        debug!("Cleaning up spent cache");
        
        let mut result = CompactionResult::default();
        
        if self.config.cache_spent {
            // Remove old spent entries
            let cutoff_height = self.database.get_current_height()?.saturating_sub(1000);
            let removed = self.database.prune_spent_cache(cutoff_height)?;
            
            result.utxos_processed = removed as u64;
            debug!("Removed {} old spent cache entries", removed);
        }
        
        Ok(result)
    }
    
    /// Rebuild database indexes
    async fn rebuild_indexes(&self) -> Result<CompactionResult> {
        debug!("Rebuilding indexes");
        
        let mut result = CompactionResult::default();
        
        // Rebuild address index
        self.database.rebuild_address_index()?;
        
        // Rebuild height index
        self.database.rebuild_height_index()?;
        
        // Compact database files
        self.database.compact()?;
        
        Ok(result)
    }
    
    /// Run automatic compaction in background
    pub async fn run_auto_compaction(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.config.compact_interval);
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.compact().await {
                error!("Auto-compaction failed: {}", e);
            }
        }
    }
    
    /// Get compaction statistics
    pub async fn get_stats(&self) -> CompactionStats {
        self.stats.read().await.clone()
    }
}

/// UTXO set statistics
#[derive(Debug, Default)]
pub struct UtxoSetStats {
    pub utxo_count: usize,
    pub total_size: u64,
    pub dust_outputs: usize,
    pub small_outputs: usize,
    pub medium_outputs: usize,
    pub large_outputs: usize,
    pub p2pkh_outputs: usize,
    pub p2sh_outputs: usize,
    pub p2wpkh_outputs: usize,
    pub p2wsh_outputs: usize,
}

/// Compaction result
#[derive(Debug, Default)]
pub struct CompactionResult {
    pub duration: Duration,
    pub utxos_processed: u64,
    pub bytes_saved: u64,
    pub errors: u32,
}

impl CompactionResult {
    fn add(&mut self, other: CompactionResult) {
        self.utxos_processed += other.utxos_processed;
        self.bytes_saved += other.bytes_saved;
        self.errors += other.errors;
    }
}

/// Script template for compression
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
enum ScriptTemplate {
    P2PKH([u8; 20]),
    P2SH([u8; 20]),
    P2WPKH([u8; 20]),
    P2WSH([u8; 32]),
    P2TR([u8; 32]),
    Multisig(Vec<Vec<u8>>, u8, u8), // pubkeys, m, n
    Custom(Vec<u8>),
}

impl ScriptTemplate {
    fn from_script(script: &ScriptBuf) -> Self {
        if script.is_p2pkh() {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&script.as_bytes()[3..23]);
            ScriptTemplate::P2PKH(hash)
        } else if script.is_p2sh() {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&script.as_bytes()[2..22]);
            ScriptTemplate::P2SH(hash)
        } else if script.is_p2wpkh() {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&script.as_bytes()[2..22]);
            ScriptTemplate::P2WPKH(hash)
        } else if script.is_p2wsh() {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&script.as_bytes()[2..34]);
            ScriptTemplate::P2WSH(hash)
        } else if script.is_p2tr() {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&script.as_bytes()[2..34]);
            ScriptTemplate::P2TR(hash)
        } else {
            ScriptTemplate::Custom(script.to_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_compaction_config() {
        let config = CompactionConfig::default();
        assert_eq!(config.min_utxos, 1_000_000);
        assert_eq!(config.batch_size, 10_000);
        assert!(config.auto_compact);
    }
    
    #[test]
    fn test_script_template() {
        use bitcoin::ScriptBuf;
        use bitcoin::script::Builder;
        
        // Test P2PKH detection
        let p2pkh = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_DUP)
            .push_opcode(bitcoin::opcodes::all::OP_HASH160)
            .push_slice(&[0u8; 20])
            .push_opcode(bitcoin::opcodes::all::OP_EQUALVERIFY)
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script();
        
        match ScriptTemplate::from_script(&p2pkh) {
            ScriptTemplate::P2PKH(_) => {}
            _ => panic!("Should be P2PKH"),
        }
    }
}