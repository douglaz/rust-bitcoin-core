use anyhow::{Context, Result};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Pruning manager for reducing storage requirements
pub struct PruningManager {
    /// Storage path
    storage_path: PathBuf,

    /// Pruning configuration
    config: PruningConfig,

    /// Block file index
    block_files: Arc<RwLock<BlockFileIndex>>,

    /// Pruning state
    state: Arc<RwLock<PruningState>>,

    /// Statistics
    stats: Arc<RwLock<PruningStats>>,
}

/// Pruning configuration
#[derive(Debug, Clone)]
pub struct PruningConfig {
    /// Enable pruning
    pub enabled: bool,

    /// Target storage size in bytes (0 = automatic)
    pub target_size: u64,

    /// Minimum blocks to keep (at least 288 for reorgs)
    pub min_blocks_to_keep: u32,

    /// Keep blocks newer than this many days
    pub keep_days: Option<u32>,

    /// Prune undo data
    pub prune_undo: bool,

    /// Automatic pruning interval
    pub auto_prune_interval: Duration,

    /// Maximum files to prune per batch
    pub max_files_per_batch: usize,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target_size: 0,          // Will be calculated based on available space
            min_blocks_to_keep: 288, // 2 days worth
            keep_days: None,
            prune_undo: true,
            auto_prune_interval: Duration::from_secs(3600), // 1 hour
            max_files_per_batch: 10,
        }
    }
}

/// Block file index
#[derive(Debug)]
struct BlockFileIndex {
    /// Map from file number to file info
    files: HashMap<u32, BlockFile>,

    /// Map from block height to file number
    #[allow(dead_code)]
    height_to_file: HashMap<u32, u32>,

    /// Current write file
    current_file: u32,

    /// Total size of all block files
    total_size: u64,
}

/// Individual block file information
#[derive(Debug, Clone)]
struct BlockFile {
    pub number: u32,
    pub path: PathBuf,
    pub size: u64,
    pub block_count: u32,
    pub height_range: (u32, u32),
    #[allow(dead_code)]
    pub can_prune: bool,
    pub is_pruned: bool,
    #[allow(dead_code)]
    pub last_modified: std::time::SystemTime,
}

/// Pruning state
#[derive(Debug)]
struct PruningState {
    /// Lowest unpruned block
    pub lowest_unpruned: u32,

    /// Highest pruned block
    pub highest_pruned: Option<u32>,

    /// Files marked for pruning
    #[allow(dead_code)]
    pub files_to_prune: VecDeque<u32>,

    /// Active pruning operation
    pub is_pruning: bool,

    /// Last prune time
    pub last_prune: Option<Instant>,
}

/// Pruning statistics
#[derive(Debug, Default, Clone)]
pub struct PruningStats {
    pub blocks_pruned: u64,
    pub files_pruned: u64,
    pub bytes_pruned: u64,
    pub current_usage: u64,
    pub target_usage: u64,
    pub prune_operations: u64,
}

impl PruningManager {
    /// Create new pruning manager
    pub fn new(storage_path: impl AsRef<Path>, config: PruningConfig) -> Result<Self> {
        let storage_path = storage_path.as_ref().to_path_buf();

        // Initialize block file index
        let block_files = Arc::new(RwLock::new(BlockFileIndex {
            files: HashMap::new(),
            height_to_file: HashMap::new(),
            current_file: 0,
            total_size: 0,
        }));

        let state = Arc::new(RwLock::new(PruningState {
            lowest_unpruned: 0,
            highest_pruned: None,
            files_to_prune: VecDeque::new(),
            is_pruning: false,
            last_prune: None,
        }));

        Ok(Self {
            storage_path,
            config,
            block_files,
            state,
            stats: Arc::new(RwLock::new(PruningStats::default())),
        })
    }

    /// Initialize pruning manager
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("Pruning is disabled");
            return Ok(());
        }

        info!("Initializing pruning manager");

        // Scan existing block files
        self.scan_block_files().await?;

        // Calculate target size if automatic
        if self.config.target_size == 0 {
            self.calculate_target_size().await?;
        }

        // Load pruning state
        self.load_state().await?;

        info!(
            "Pruning initialized with target size: {} GB",
            self.config.target_size / 1_000_000_000
        );

        Ok(())
    }

    /// Scan existing block files
    async fn scan_block_files(&self) -> Result<()> {
        let blocks_dir = self.storage_path.join("blocks");
        if !blocks_dir.exists() {
            return Ok(());
        }

        let mut files = self.block_files.write().await;
        let mut total_size = 0u64;

        // Scan blk*.dat files
        for entry in std::fs::read_dir(&blocks_dir)? {
            let entry = entry?;
            let path = entry.path();

            if let Some(name) = path.file_name() {
                if let Some(name_str) = name.to_str() {
                    if name_str.starts_with("blk") && name_str.ends_with(".dat") {
                        // Parse file number
                        if let Ok(num) = name_str[3..name_str.len() - 4].parse::<u32>() {
                            let metadata = entry.metadata()?;
                            let size = metadata.len();

                            let block_file = BlockFile {
                                number: num,
                                path: path.clone(),
                                size,
                                block_count: 0, // Will be updated later
                                height_range: (0, 0),
                                can_prune: false,
                                is_pruned: false,
                                last_modified: metadata.modified()?,
                            };

                            files.files.insert(num, block_file);
                            total_size += size;

                            if num > files.current_file {
                                files.current_file = num;
                            }
                        }
                    }
                }
            }
        }

        files.total_size = total_size;
        debug!(
            "Found {} block files, total size: {} MB",
            files.files.len(),
            total_size / 1_000_000
        );

        Ok(())
    }

    /// Calculate target size based on available disk space
    async fn calculate_target_size(&self) -> Result<()> {
        // Simplified: use configured target size instead of checking disk space
        // In production, would use platform-specific APIs or external crate
        let target_size = self.config.target_size;

        info!(
            "Using configured target size: {} MB",
            target_size / 1_000_000
        );

        // For now, just use the configured size
        let target = target_size;

        info!("Target pruning size: {} GB", target / 1_000_000_000);

        Ok(())
    }

    /// Load pruning state from disk
    async fn load_state(&self) -> Result<()> {
        let state_file = self.storage_path.join("pruning_state.json");

        if state_file.exists() {
            let data = tokio::fs::read_to_string(&state_file).await?;
            let saved_state: SavedPruningState = serde_json::from_str(&data)?;

            let mut state = self.state.write().await;
            state.lowest_unpruned = saved_state.lowest_unpruned;
            state.highest_pruned = saved_state.highest_pruned;

            debug!(
                "Loaded pruning state: lowest_unpruned={}, highest_pruned={:?}",
                state.lowest_unpruned, state.highest_pruned
            );
        }

        Ok(())
    }

    /// Save pruning state to disk
    async fn save_state(&self) -> Result<()> {
        let state = self.state.read().await;

        let saved_state = SavedPruningState {
            lowest_unpruned: state.lowest_unpruned,
            highest_pruned: state.highest_pruned,
        };

        let state_file = self.storage_path.join("pruning_state.json");
        let data = serde_json::to_string(&saved_state)?;
        tokio::fs::write(&state_file, data).await?;

        Ok(())
    }

    /// Check if pruning is needed
    pub async fn should_prune(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        let files = self.block_files.read().await;
        files.total_size > self.config.target_size
    }

    /// Prune old blocks
    pub async fn prune(&self) -> Result<PruneResult> {
        if !self.config.enabled {
            return Ok(PruneResult::default());
        }

        // Check if already pruning
        {
            let mut state = self.state.write().await;
            if state.is_pruning {
                debug!("Pruning already in progress");
                return Ok(PruneResult::default());
            }
            state.is_pruning = true;
        }

        let result = self.prune_internal().await;

        // Clear pruning flag
        {
            let mut state = self.state.write().await;
            state.is_pruning = false;
            state.last_prune = Some(Instant::now());
        }

        // Save state
        if let Err(e) = self.save_state().await {
            error!("Failed to save pruning state: {}", e);
        }

        result
    }

    /// Internal pruning logic
    async fn prune_internal(&self) -> Result<PruneResult> {
        let mut result = PruneResult::default();

        // Determine which files can be pruned
        let files_to_prune = self.select_files_to_prune().await?;

        if files_to_prune.is_empty() {
            debug!("No files eligible for pruning");
            return Ok(result);
        }

        info!("Pruning {} block files", files_to_prune.len());

        // Prune each file
        for file_num in files_to_prune {
            match self.prune_file(file_num).await {
                Ok(file_result) => {
                    result.files_pruned += 1;
                    result.blocks_pruned += file_result.blocks_pruned;
                    result.bytes_freed += file_result.bytes_freed;
                }
                Err(e) => {
                    error!("Failed to prune file {}: {}", file_num, e);
                    result.errors += 1;
                }
            }

            // Check if we've freed enough space
            let files = self.block_files.read().await;
            if files.total_size <= self.config.target_size {
                break;
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.files_pruned += result.files_pruned as u64;
            stats.blocks_pruned += result.blocks_pruned as u64;
            stats.bytes_pruned += result.bytes_freed;
            stats.prune_operations += 1;

            let files = self.block_files.read().await;
            stats.current_usage = files.total_size;
            stats.target_usage = self.config.target_size;
        }

        info!(
            "Pruning complete: {} files, {} blocks, {} MB freed",
            result.files_pruned,
            result.blocks_pruned,
            result.bytes_freed / 1_000_000
        );

        Ok(result)
    }

    /// Select files to prune
    async fn select_files_to_prune(&self) -> Result<Vec<u32>> {
        let mut files_to_prune = Vec::new();
        let files = self.block_files.read().await;
        let _state = self.state.read().await;

        // Get current block height (would come from chain manager)
        let current_height = 800000u32; // Placeholder

        // Sort files by height
        let mut sorted_files: Vec<_> = files.files.values().filter(|f| !f.is_pruned).collect();
        sorted_files.sort_by_key(|f| f.height_range.1);

        for file in sorted_files {
            // Check if file is old enough to prune
            let newest_block = file.height_range.1;

            if newest_block < current_height.saturating_sub(self.config.min_blocks_to_keep) {
                // Check if file contains any important blocks
                if !self.contains_important_blocks(file).await {
                    files_to_prune.push(file.number);

                    if files_to_prune.len() >= self.config.max_files_per_batch {
                        break;
                    }
                }
            }
        }

        Ok(files_to_prune)
    }

    /// Check if file contains important blocks
    async fn contains_important_blocks(&self, _file: &BlockFile) -> bool {
        // Check for:
        // - Wallet transactions
        // - Recent blocks
        // - Checkpoint blocks
        // For now, simplified check
        false
    }

    /// Prune a specific file
    async fn prune_file(&self, file_num: u32) -> Result<PruneFileResult> {
        let file_info = {
            let files = self.block_files.read().await;
            files
                .files
                .get(&file_num)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("File {} not found", file_num))?
        };

        debug!(
            "Pruning file {}: {} MB",
            file_num,
            file_info.size / 1_000_000
        );

        // Delete the actual file
        if file_info.path.exists() {
            tokio::fs::remove_file(&file_info.path)
                .await
                .context("Failed to delete block file")?;
        }

        // Delete corresponding undo file if configured
        if self.config.prune_undo {
            let undo_path = file_info
                .path
                .with_file_name(format!("rev{:05}.dat", file_num));
            if undo_path.exists() {
                tokio::fs::remove_file(&undo_path)
                    .await
                    .context("Failed to delete undo file")?;
            }
        }

        // Update index
        {
            let mut files = self.block_files.write().await;
            if let Some(file) = files.files.get_mut(&file_num) {
                let file_size = file.size;
                file.is_pruned = true;
                files.total_size = files.total_size.saturating_sub(file_size);
            }
        }

        // Update state
        {
            let mut state = self.state.write().await;
            if state
                .highest_pruned
                .map_or(true, |h| file_info.height_range.1 > h)
            {
                state.highest_pruned = Some(file_info.height_range.1);
            }
            state.lowest_unpruned = file_info.height_range.1 + 1;
        }

        Ok(PruneFileResult {
            blocks_pruned: file_info.block_count,
            bytes_freed: file_info.size,
        })
    }

    /// Check if a block is available (not pruned)
    pub async fn is_block_available(&self, height: u32) -> bool {
        if !self.config.enabled {
            return true; // All blocks available if not pruning
        }

        let state = self.state.read().await;

        if let Some(highest_pruned) = state.highest_pruned {
            height > highest_pruned
        } else {
            true // Nothing pruned yet
        }
    }

    /// Get pruning statistics
    pub async fn get_stats(&self) -> PruningStats {
        self.stats.read().await.clone()
    }

    /// Run automatic pruning loop
    pub async fn run_auto_pruning(self: Arc<Self>) {
        if !self.config.enabled {
            return;
        }

        let mut interval = tokio::time::interval(self.config.auto_prune_interval);

        loop {
            interval.tick().await;

            if self.should_prune().await {
                if let Err(e) = self.prune().await {
                    error!("Auto-pruning failed: {}", e);
                }
            }
        }
    }
}

/// Saved pruning state
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SavedPruningState {
    lowest_unpruned: u32,
    highest_pruned: Option<u32>,
}

/// Prune result
#[derive(Debug, Default)]
pub struct PruneResult {
    pub files_pruned: usize,
    pub blocks_pruned: u32,
    pub bytes_freed: u64,
    pub errors: usize,
}

/// Prune file result
#[derive(Debug)]
struct PruneFileResult {
    blocks_pruned: u32,
    bytes_freed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_pruning_manager() {
        let temp_dir = TempDir::new().unwrap();
        let config = PruningConfig {
            enabled: true,
            target_size: 1_000_000, // 1 MB
            ..Default::default()
        };

        let manager = PruningManager::new(temp_dir.path(), config).unwrap();
        manager.initialize().await.unwrap();

        // Check if pruning is needed
        assert!(!manager.should_prune().await);

        // Check block availability
        assert!(manager.is_block_available(100).await);
    }
}
