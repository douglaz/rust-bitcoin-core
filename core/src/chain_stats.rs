use anyhow::{Context, Result};
use bitcoin::block::Header as BlockHeader;
use bitcoin::BlockHash;
use tracing::debug;

/// Calculate median time past for a block
pub fn calculate_median_time_past(headers: &[BlockHeader], _current_height: u32) -> Result<u32> {
    // Bitcoin uses median of last 11 blocks
    const MEDIAN_TIME_SPAN: usize = 11;

    if headers.is_empty() {
        return Ok(0);
    }

    // Get the last 11 blocks (or fewer if not available)
    let start_idx = if headers.len() > MEDIAN_TIME_SPAN {
        headers.len() - MEDIAN_TIME_SPAN
    } else {
        0
    };

    let mut timestamps: Vec<u32> = headers[start_idx..].iter().map(|h| h.time).collect();

    // Sort timestamps
    timestamps.sort();

    // Return median
    let median = if timestamps.is_empty() {
        0
    } else if timestamps.len() % 2 == 0 {
        // Even number of elements, average the two middle values
        let mid = timestamps.len() / 2;
        (timestamps[mid - 1] + timestamps[mid]) / 2
    } else {
        // Odd number of elements, return the middle value
        timestamps[timestamps.len() / 2]
    };

    debug!(
        "Calculated median time past: {} from {} blocks",
        median,
        timestamps.len()
    );
    Ok(median)
}

/// Calculate accumulated chain work
pub fn calculate_chain_work(headers: &[BlockHeader]) -> Result<String> {
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    let mut total_work = BigUint::zero();

    for header in headers {
        // Work = 2^256 / (target + 1)
        let target = header.target();
        let target_bytes = target.to_le_bytes();
        let target_value = BigUint::from_bytes_le(&target_bytes);

        // 2^256
        let max_target = BigUint::one() << 256;

        // Work for this block
        let work = &max_target / (&target_value + BigUint::one());
        total_work += work;
    }

    // Convert to hex string (with leading zeros for consistent length)
    let hex = format!("{:064x}", total_work);

    debug!("Total chain work: {}", hex);
    Ok(hex)
}

/// Calculate blockchain size on disk
pub async fn calculate_size_on_disk(storage_path: &std::path::Path) -> Result<u64> {
    use futures::stream::{self, StreamExt};
    use tokio::fs;

    let mut total_size = 0u64;

    // Walk the directory recursively
    let mut entries = fs::read_dir(storage_path)
        .await
        .context("Failed to read storage directory")?;

    let mut paths = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        paths.push(entry.path());
    }

    // Process files in parallel
    let sizes: Vec<u64> = stream::iter(paths)
        .then(|path| async move {
            if path.is_file() {
                match fs::metadata(&path).await {
                    Ok(meta) => meta.len(),
                    Err(_) => 0,
                }
            } else if path.is_dir() {
                // Recursively calculate subdirectory size
                calculate_dir_size(&path).await.unwrap_or(0)
            } else {
                0
            }
        })
        .collect()
        .await;

    total_size = sizes.iter().sum();

    debug!("Total blockchain size on disk: {} bytes", total_size);
    Ok(total_size)
}

async fn calculate_dir_size(dir: &std::path::Path) -> Result<u64> {
    use tokio::fs;

    let mut size = 0u64;
    let mut entries = fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = fs::metadata(&path).await?;

        if metadata.is_file() {
            size += metadata.len();
        } else if metadata.is_dir() {
            size += Box::pin(calculate_dir_size(&path)).await?;
        }
    }

    Ok(size)
}

/// Get detailed chain statistics
pub struct ChainStatistics {
    pub height: u32,
    pub best_block_hash: BlockHash,
    pub median_time: u32,
    pub chain_work: String,
    pub size_on_disk: u64,
    pub tx_count: u64,
    pub utxo_count: u64,
    pub total_supply: u64,
}

impl ChainStatistics {
    pub async fn calculate(
        headers: &[BlockHeader],
        height: u32,
        best_hash: BlockHash,
        storage_path: &std::path::Path,
        utxo_count: u64,
    ) -> Result<Self> {
        let median_time = calculate_median_time_past(headers, height)?;
        let chain_work = calculate_chain_work(headers)?;
        let size_on_disk = calculate_size_on_disk(storage_path).await?;

        // Calculate total supply based on height
        let total_supply = calculate_total_supply(height);

        // Estimate tx count (rough approximation)
        let tx_count = estimate_tx_count(height);

        Ok(Self {
            height,
            best_block_hash: best_hash,
            median_time,
            chain_work,
            size_on_disk,
            tx_count,
            utxo_count,
            total_supply,
        })
    }
}

/// Calculate total Bitcoin supply at a given height
fn calculate_total_supply(height: u32) -> u64 {
    let mut total = 0u64;
    let mut subsidy = 50_0000_0000u64; // 50 BTC in satoshis
    let mut current_height = 0u32;

    while current_height < height {
        let blocks_until_halving = 210_000 - (current_height % 210_000);
        let blocks_at_current_subsidy = blocks_until_halving.min(height - current_height);

        total += subsidy * blocks_at_current_subsidy as u64;
        current_height += blocks_at_current_subsidy;

        // Halving every 210,000 blocks
        if current_height % 210_000 == 0 && current_height > 0 {
            subsidy /= 2;
        }
    }

    total
}

/// Rough estimation of transaction count based on height
fn estimate_tx_count(height: u32) -> u64 {
    // Very rough approximation: average ~2000 tx per block after block 100k
    if height < 100_000 {
        height as u64 * 10
    } else {
        1_000_000 + ((height - 100_000) as u64 * 2000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_median_time_calculation() {
        let headers = vec![
            create_test_header(100),
            create_test_header(102),
            create_test_header(104),
            create_test_header(103),
            create_test_header(105),
        ];

        let median = calculate_median_time_past(&headers, 5).unwrap();
        assert_eq!(median, 103); // Middle value when sorted
    }

    #[test]
    fn test_total_supply_calculation() {
        // At height 0: 0 BTC
        assert_eq!(calculate_total_supply(0), 0);

        // At height 1: 50 BTC
        assert_eq!(calculate_total_supply(1), 50_0000_0000);

        // At height 210,000: 10,500,000 BTC
        assert_eq!(calculate_total_supply(210_000), 210_000 * 50_0000_0000);

        // After first halving
        assert_eq!(
            calculate_total_supply(210_001),
            210_000 * 50_0000_0000 + 25_0000_0000
        );
    }

    fn create_test_header(time: u32) -> BlockHeader {
        BlockHeader {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash: BlockHash::from_raw_hash(
                bitcoin::hashes::Hash::from_slice(&[0u8; 32]).unwrap(),
            ),
            merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                bitcoin::hashes::Hash::from_slice(&[0u8; 32]).unwrap(),
            ),
            time,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        }
    }
}
