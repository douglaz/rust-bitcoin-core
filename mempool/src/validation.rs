use anyhow::{bail, Result};
use bitcoin::{Amount, OutPoint, Transaction};
use std::collections::{HashMap, HashSet};
use tracing::{debug, warn};

/// Transaction validation policy for mempool acceptance
pub struct MempoolPolicy {
    /// Minimum relay fee rate in satoshis per vbyte
    pub min_relay_fee_rate: u64,
    /// Maximum transaction weight
    pub max_tx_weight: usize,
    /// Maximum number of ancestors
    pub max_ancestors: usize,
    /// Maximum size of ancestor packages
    pub max_ancestor_size: usize,
    /// Maximum number of descendants
    pub max_descendants: usize,
    /// Maximum size of descendant packages
    pub max_descendant_size: usize,
    /// Allow replacement of transactions (RBF)
    pub enable_rbf: bool,
    /// Minimum fee increase for RBF
    pub min_rbf_fee_increment: u64,
    /// Maximum mempool size in bytes
    pub max_mempool_size: usize,
    /// Dust relay fee rate in satoshis per vbyte
    pub dust_relay_fee_rate: u64,
}

impl Default for MempoolPolicy {
    fn default() -> Self {
        Self {
            min_relay_fee_rate: 1,
            max_tx_weight: 400_000, // 400k weight units
            max_ancestors: 25,
            max_ancestor_size: 101_000, // 101 KB
            max_descendants: 25,
            max_descendant_size: 101_000, // 101 KB
            enable_rbf: true,
            min_rbf_fee_increment: 1000,   // 1000 satoshis
            max_mempool_size: 300_000_000, // 300 MB
            dust_relay_fee_rate: 3,
        }
    }
}

/// Package information for a transaction
#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub ancestors: HashSet<bitcoin::Txid>,
    pub descendants: HashSet<bitcoin::Txid>,
    pub ancestor_size: usize,
    pub descendant_size: usize,
    pub ancestor_fees: u64,
    pub descendant_fees: u64,
}

impl Default for PackageInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageInfo {
    pub fn new() -> Self {
        Self {
            ancestors: HashSet::new(),
            descendants: HashSet::new(),
            ancestor_size: 0,
            descendant_size: 0,
            ancestor_fees: 0,
            descendant_fees: 0,
        }
    }
}

/// Enhanced mempool transaction entry
#[derive(Debug, Clone)]
pub struct EnhancedMempoolEntry {
    pub tx: Transaction,
    pub fee: Amount,
    pub fee_rate: u64, // satoshis per vbyte
    pub weight: usize,
    pub size: usize,
    pub time: u64,
    pub height: u32,
    pub spends_coinbase: bool,
    pub sigops: u32,
    pub package_info: PackageInfo,
}

/// Mempool validation context
pub struct ValidationContext<'a> {
    pub policy: &'a MempoolPolicy,
    pub mempool_txs: &'a HashMap<bitcoin::Txid, EnhancedMempoolEntry>,
    pub spent_outputs: &'a HashMap<OutPoint, bitcoin::Txid>,
}

/// Validate transaction against mempool policy
pub fn validate_mempool_acceptance(
    tx: &Transaction,
    fee: Amount,
    ctx: &ValidationContext,
) -> Result<()> {
    let txid = tx.compute_txid();
    let tx_weight = tx.weight().to_wu() as usize;
    let tx_vsize = tx_weight.div_ceil(4);
    let fee_rate = fee.to_sat() / tx_vsize as u64;

    debug!("Validating transaction {} for mempool acceptance", txid);

    // 1. Check transaction weight
    if tx_weight > ctx.policy.max_tx_weight {
        bail!(
            "Transaction weight {} exceeds maximum {}",
            tx_weight,
            ctx.policy.max_tx_weight
        );
    }

    // 2. Check minimum relay fee
    if fee_rate < ctx.policy.min_relay_fee_rate {
        bail!(
            "Transaction fee rate {} sat/vB below minimum {}",
            fee_rate,
            ctx.policy.min_relay_fee_rate
        );
    }

    // 3. Check for dust outputs
    for (idx, output) in tx.output.iter().enumerate() {
        if is_dust_output(output, ctx.policy.dust_relay_fee_rate) {
            bail!("Output {} is dust", idx);
        }
    }

    // 4. Check for conflicts (double spends)
    let conflicts = find_conflicts(tx, ctx.spent_outputs);
    if !conflicts.is_empty() && ctx.policy.enable_rbf {
        // Handle RBF
        validate_rbf_replacement(tx, fee, &conflicts, ctx)?;
    } else if !conflicts.is_empty() {
        bail!(
            "Transaction conflicts with {} existing transactions",
            conflicts.len()
        );
    }

    // 5. Check package limits
    let package_info = calculate_package_info(tx, ctx.mempool_txs);

    if package_info.ancestors.len() > ctx.policy.max_ancestors {
        bail!(
            "Transaction has {} ancestors, exceeds limit of {}",
            package_info.ancestors.len(),
            ctx.policy.max_ancestors
        );
    }

    if package_info.ancestor_size > ctx.policy.max_ancestor_size {
        bail!(
            "Ancestor package size {} exceeds limit of {}",
            package_info.ancestor_size,
            ctx.policy.max_ancestor_size
        );
    }

    // 6. Check standard transaction types
    validate_standard_transaction(tx)?;

    Ok(())
}

/// Check if output is dust
fn is_dust_output(output: &bitcoin::TxOut, dust_relay_fee_rate: u64) -> bool {
    // Calculate dust threshold based on output type
    let dust_threshold = calculate_dust_threshold(&output.script_pubkey, dust_relay_fee_rate);
    output.value.to_sat() < dust_threshold
}

/// Calculate dust threshold for an output
fn calculate_dust_threshold(script_pubkey: &bitcoin::ScriptBuf, dust_rate: u64) -> u64 {
    // Base size: 8 bytes value + compact size for script length
    let mut size = 8 + 1;

    // Add script size
    size += script_pubkey.len();

    // Add input size when spending
    // P2PKH input: 148 bytes
    // P2WPKH input: 67.75 vbytes
    // P2TR input: 57.5 vbytes
    let input_size = if script_pubkey.is_p2pkh() {
        148
    } else if script_pubkey.is_p2wpkh() {
        68
    } else if script_pubkey.is_p2tr() {
        58
    } else {
        148 // Conservative estimate
    };

    size += input_size;

    // Dust threshold = size * dust_rate
    size as u64 * dust_rate
}

/// Find conflicting transactions
fn find_conflicts(
    tx: &Transaction,
    spent_outputs: &HashMap<OutPoint, bitcoin::Txid>,
) -> HashSet<bitcoin::Txid> {
    let mut conflicts = HashSet::new();

    for input in &tx.input {
        if let Some(conflicting_tx) = spent_outputs.get(&input.previous_output) {
            conflicts.insert(*conflicting_tx);
        }
    }

    conflicts
}

/// Validate RBF replacement
fn validate_rbf_replacement(
    new_tx: &Transaction,
    new_fee: Amount,
    conflicts: &HashSet<bitcoin::Txid>,
    ctx: &ValidationContext,
) -> Result<()> {
    // Check BIP125 rules for RBF

    // Rule 1: Original transactions must signal replaceability
    for conflict_txid in conflicts {
        if let Some(entry) = ctx.mempool_txs.get(conflict_txid) {
            if !is_rbf_signaling(&entry.tx) {
                bail!("Original transaction {} does not signal RBF", conflict_txid);
            }
        }
    }

    // Rule 2: No new unconfirmed inputs
    // (simplified - in practice would check all inputs)

    // Rule 3: Replacement must pay higher fee
    let mut total_replaced_fee = 0u64;
    let mut total_replaced_size = 0usize;

    for conflict_txid in conflicts {
        if let Some(entry) = ctx.mempool_txs.get(conflict_txid) {
            total_replaced_fee += entry.fee.to_sat();
            total_replaced_size += entry.size;
        }
    }

    if new_fee.to_sat() <= total_replaced_fee {
        bail!(
            "Replacement fee {} must be higher than original {}",
            new_fee.to_sat(),
            total_replaced_fee
        );
    }

    // Rule 4: Additional fee must cover bandwidth
    let min_additional_fee = ctx.policy.min_rbf_fee_increment;
    if new_fee.to_sat() < total_replaced_fee + min_additional_fee {
        bail!(
            "Replacement must pay at least {} sats more in fees",
            min_additional_fee
        );
    }

    Ok(())
}

/// Check if transaction signals RBF
fn is_rbf_signaling(tx: &Transaction) -> bool {
    // BIP125: Transaction is replaceable if any input has sequence < 0xfffffffe
    tx.input.iter().any(|input| input.sequence.0 < 0xfffffffe)
}

/// Calculate package information for a transaction
pub fn calculate_package_info(
    tx: &Transaction,
    mempool_txs: &HashMap<bitcoin::Txid, EnhancedMempoolEntry>,
) -> PackageInfo {
    let mut package_info = PackageInfo::new();
    let mut visited_ancestors = HashSet::new();

    // Find ancestors (transactions this tx depends on)
    let mut to_visit = Vec::new();

    // Start with direct parents
    for input in &tx.input {
        if mempool_txs.contains_key(&input.previous_output.txid) {
            to_visit.push(input.previous_output.txid);
        }
    }

    // BFS to find all ancestors
    while let Some(ancestor_txid) = to_visit.pop() {
        if visited_ancestors.contains(&ancestor_txid) {
            continue;
        }

        if let Some(ancestor_entry) = mempool_txs.get(&ancestor_txid) {
            visited_ancestors.insert(ancestor_txid);
            package_info.ancestors.insert(ancestor_txid);
            package_info.ancestor_size += ancestor_entry.size;
            package_info.ancestor_fees += ancestor_entry.fee.to_sat();

            // Add this ancestor's parents to visit
            for input in &ancestor_entry.tx.input {
                if mempool_txs.contains_key(&input.previous_output.txid)
                    && !visited_ancestors.contains(&input.previous_output.txid)
                {
                    to_visit.push(input.previous_output.txid);
                }
            }
        }
    }

    // Find descendants (transactions that spend this tx's outputs)
    let txid = tx.compute_txid();
    let mut visited_descendants = HashSet::new();
    let mut to_visit_desc = Vec::new();

    // Start by finding direct children
    for (child_txid, child_entry) in mempool_txs {
        for input in &child_entry.tx.input {
            if input.previous_output.txid == txid {
                to_visit_desc.push(*child_txid);
                break;
            }
        }
    }

    // BFS to find all descendants
    while let Some(desc_txid) = to_visit_desc.pop() {
        if visited_descendants.contains(&desc_txid) {
            continue;
        }

        if let Some(desc_entry) = mempool_txs.get(&desc_txid) {
            visited_descendants.insert(desc_txid);
            package_info.descendants.insert(desc_txid);
            package_info.descendant_size += desc_entry.size;
            package_info.descendant_fees += desc_entry.fee.to_sat();

            // Find this descendant's children
            for (child_txid, child_entry) in mempool_txs {
                if visited_descendants.contains(child_txid) {
                    continue;
                }
                for input in &child_entry.tx.input {
                    if input.previous_output.txid == desc_txid {
                        to_visit_desc.push(*child_txid);
                        break;
                    }
                }
            }
        }
    }

    package_info
}

/// Validate standard transaction types
fn validate_standard_transaction(tx: &Transaction) -> Result<()> {
    // Check version
    if tx.version.0 < 1 || tx.version.0 > 2 {
        bail!("Non-standard transaction version: {}", tx.version);
    }

    // Check for standard script types in outputs
    for (idx, output) in tx.output.iter().enumerate() {
        if !is_standard_script(&output.script_pubkey) {
            warn!("Output {} has non-standard script", idx);
            // Could bail here if strict policy
        }
    }

    // Check script sig sizes aren't too large
    for (idx, input) in tx.input.iter().enumerate() {
        if input.script_sig.len() > 1650 {
            bail!(
                "Input {} scriptSig too large: {}",
                idx,
                input.script_sig.len()
            );
        }
    }

    Ok(())
}

/// Check if script is standard
fn is_standard_script(script: &bitcoin::ScriptBuf) -> bool {
    script.is_p2pk()
        || script.is_p2pkh()
        || script.is_p2sh()
        || script.is_p2wpkh()
        || script.is_p2wsh()
        || script.is_p2tr()
        || script.is_op_return()
}

/// Validate transaction dependencies
pub fn validate_dependencies(
    tx: &Transaction,
    mempool_txs: &HashMap<bitcoin::Txid, EnhancedMempoolEntry>,
) -> Result<Vec<bitcoin::Txid>> {
    let mut missing_deps = Vec::new();

    for input in &tx.input {
        let parent_txid = input.previous_output.txid;

        // Check if parent is in mempool
        if !mempool_txs.contains_key(&parent_txid) {
            // Parent might be confirmed, which is fine
            // But if not confirmed and not in mempool, it's missing
            missing_deps.push(parent_txid);
        }
    }

    if !missing_deps.is_empty() {
        debug!(
            "Transaction has {} missing dependencies",
            missing_deps.len()
        );
    }

    Ok(missing_deps)
}

/// Calculate effective fee rate including ancestors
pub fn calculate_mining_score(tx: &Transaction, fee: Amount, package_info: &PackageInfo) -> u64 {
    let tx_weight = tx.weight().to_wu();
    let tx_vsize = tx_weight.div_ceil(4);

    // Include ancestor fees and size for mining score
    let total_fees = fee.to_sat() + package_info.ancestor_fees;
    let total_size = tx_vsize + package_info.ancestor_size as u64;

    if total_size == 0 {
        return 0;
    }

    total_fees / total_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_dust_threshold_calculation() {
        // Test P2PKH dust threshold
        let p2pkh_script = bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::all_zeros());
        let threshold = calculate_dust_threshold(&p2pkh_script, 3);
        assert!(threshold > 0);

        // Test P2WPKH dust threshold (should be lower)
        let p2wpkh_script = bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros());
        let wpkh_threshold = calculate_dust_threshold(&p2wpkh_script, 3);
        assert!(wpkh_threshold < threshold);
    }

    #[test]
    fn test_rbf_signaling() {
        use bitcoin::{OutPoint, Sequence, TxIn};

        // Create transaction with RBF signaling
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // 0xfffffffd
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };

        assert!(is_rbf_signaling(&tx));

        // Change to non-RBF
        tx.input[0].sequence = Sequence::MAX;
        assert!(!is_rbf_signaling(&tx));
    }
}
