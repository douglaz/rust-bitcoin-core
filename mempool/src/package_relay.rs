use anyhow::{bail, Result};
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::validation::{EnhancedMempoolEntry, MempoolPolicy, PackageInfo};
use crate::rbf::RBFPolicy;

/// Maximum number of transactions in a package
pub const MAX_PACKAGE_COUNT: usize = 25;

/// Maximum total size of a package in bytes
pub const MAX_PACKAGE_SIZE: usize = 101_000;

/// Maximum total weight of a package in weight units
pub const MAX_PACKAGE_WEIGHT: usize = 404_000;

/// Package type for relay
#[derive(Debug, Clone, PartialEq)]
pub enum PackageType {
    /// Child with unconfirmed parents
    ChildWithParents,
    /// Transaction with all ancestors
    AncestorPackage,
    /// Transaction with all descendants
    DescendantPackage,
}

/// Transaction package for atomic acceptance
#[derive(Debug, Clone)]
pub struct Package {
    /// Transactions in topological order (parents before children)
    pub transactions: Vec<Transaction>,
    
    /// Package type
    pub package_type: PackageType,
    
    /// Total fee of all transactions
    pub total_fee: Amount,
    
    /// Total weight of all transactions
    pub total_weight: usize,
    
    /// Total size in bytes
    pub total_size: usize,
    
    /// Combined fee rate (total_fee / total_weight * 4)
    pub package_feerate: f64,
    
    /// Transaction IDs in the package
    pub txids: Vec<Txid>,
    
    /// Parent-child relationships
    pub relationships: HashMap<Txid, HashSet<Txid>>,
}

impl Package {
    /// Create a new package from transactions
    pub fn new(transactions: Vec<Transaction>, package_type: PackageType) -> Result<Self> {
        if transactions.is_empty() {
            bail!("Package cannot be empty");
        }
        
        if transactions.len() > MAX_PACKAGE_COUNT {
            bail!(
                "Package contains {} transactions, exceeds limit of {}",
                transactions.len(),
                MAX_PACKAGE_COUNT
            );
        }
        
        // Calculate totals
        // Note: In production, fee would be calculated by comparing inputs vs outputs
        // For testing, we'll use a default fee per transaction
        let mut total_fee = Amount::ZERO;
        let mut total_weight = 0usize;
        let mut total_size = 0usize;
        let mut txids = Vec::new();
        let mut relationships = HashMap::new();
        
        // Build transaction index
        let tx_map: HashMap<Txid, &Transaction> = transactions
            .iter()
            .map(|tx| (tx.compute_txid(), tx))
            .collect();
        
        for tx in &transactions {
            let txid = tx.compute_txid();
            txids.push(txid);
            
            let weight = tx.weight().to_wu() as usize;
            total_weight += weight;
            
            let size = bitcoin::consensus::serialize(tx).len();
            total_size += size;
            
            // Find parent transactions within the package
            let mut parents = HashSet::new();
            for input in &tx.input {
                if let Some(parent_tx) = tx_map.get(&input.previous_output.txid) {
                    parents.insert(parent_tx.compute_txid());
                }
            }
            
            if !parents.is_empty() {
                relationships.insert(txid, parents);
            }
        }
        
        // Validate package limits
        if total_size > MAX_PACKAGE_SIZE {
            bail!(
                "Package size {} bytes exceeds limit of {} bytes",
                total_size,
                MAX_PACKAGE_SIZE
            );
        }
        
        if total_weight > MAX_PACKAGE_WEIGHT {
            bail!(
                "Package weight {} exceeds limit of {}",
                total_weight,
                MAX_PACKAGE_WEIGHT
            );
        }
        
        // Calculate package fee rate
        let package_feerate = if total_weight > 0 {
            // Convert to sat/vB
            (total_fee.to_sat() as f64 * 4.0) / (total_weight as f64)
        } else {
            0.0
        };
        
        Ok(Self {
            transactions,
            package_type,
            total_fee,
            total_weight,
            total_size,
            package_feerate,
            txids,
            relationships,
        })
    }
    
    /// Sort transactions in topological order (parents before children)
    pub fn topological_sort(&mut self) -> Result<()> {
        let mut sorted = Vec::new();
        let mut visited = HashSet::new();
        let mut visiting = HashSet::new();
        
        // Build adjacency list (parent -> children)
        let mut children_map: HashMap<Txid, Vec<Txid>> = HashMap::new();
        for (child, parents) in &self.relationships {
            for parent in parents {
                children_map.entry(*parent).or_default().push(*child);
            }
        }
        
        // DFS to detect cycles and sort
        fn dfs(
            txid: Txid,
            tx_map: &HashMap<Txid, Transaction>,
            children_map: &HashMap<Txid, Vec<Txid>>,
            visited: &mut HashSet<Txid>,
            visiting: &mut HashSet<Txid>,
            sorted: &mut Vec<Transaction>,
        ) -> Result<()> {
            if visited.contains(&txid) {
                return Ok(());
            }
            
            if visiting.contains(&txid) {
                bail!("Package contains circular dependencies");
            }
            
            visiting.insert(txid);
            
            // Visit children first (post-order for topological sort)
            if let Some(children) = children_map.get(&txid) {
                for child in children {
                    dfs(*child, tx_map, children_map, visited, visiting, sorted)?;
                }
            }
            
            visiting.remove(&txid);
            visited.insert(txid);
            
            if let Some(tx) = tx_map.get(&txid) {
                sorted.push(tx.clone());
            }
            
            Ok(())
        }
        
        // Create transaction map
        let tx_map: HashMap<Txid, Transaction> = self.transactions
            .iter()
            .map(|tx| (tx.compute_txid(), tx.clone()))
            .collect();
        
        // Process all transactions
        for txid in &self.txids {
            dfs(*txid, &tx_map, &children_map, &mut visited, &mut visiting, &mut sorted)?;
        }
        
        // Reverse to get parents before children
        sorted.reverse();
        self.transactions = sorted;
        
        Ok(())
    }
    
    /// Check if package contains conflicting transactions
    pub fn check_conflicts(&self) -> Result<()> {
        let mut spent_outputs = HashSet::new();
        
        for tx in &self.transactions {
            for input in &tx.input {
                if !spent_outputs.insert(input.previous_output) {
                    bail!(
                        "Package contains conflicting transactions: output {:?} spent multiple times",
                        input.previous_output
                    );
                }
            }
        }
        
        Ok(())
    }
    
    /// Create a package with explicit fee for testing
    #[doc(hidden)]
    pub fn new_with_fee(
        transactions: Vec<Transaction>,
        package_type: PackageType,
        total_fee: Amount,
    ) -> Result<Self> {
        let mut package = Self::new(transactions, package_type)?;
        package.total_fee = total_fee;
        
        // Recalculate fee rate
        package.package_feerate = if package.total_weight > 0 {
            (total_fee.to_sat() as f64 * 4.0) / (package.total_weight as f64)
        } else {
            0.0
        };
        
        Ok(package)
    }
}

/// Package validator for mempool acceptance
pub struct PackageValidator {
    /// Maximum number of transactions in a package
    pub max_package_count: usize,
    
    /// Maximum total size of a package in bytes
    pub max_package_size: usize,
    
    /// Maximum total weight of a package
    pub max_package_weight: usize,
    
    /// Minimum package fee rate (sat/vB)
    pub min_package_feerate: f64,
    
    /// Allow packages with unconfirmed inputs
    pub allow_unconfirmed_inputs: bool,
}

impl Default for PackageValidator {
    fn default() -> Self {
        Self {
            max_package_count: MAX_PACKAGE_COUNT,
            max_package_size: MAX_PACKAGE_SIZE,
            max_package_weight: MAX_PACKAGE_WEIGHT,
            min_package_feerate: 1.0, // 1 sat/vB minimum
            allow_unconfirmed_inputs: true,
        }
    }
}

impl PackageValidator {
    /// Validate a package for acceptance
    pub fn validate_package(&self, package: &Package) -> Result<()> {
        // Check package count
        if package.transactions.len() > self.max_package_count {
            bail!(
                "Package contains {} transactions, exceeds limit of {}",
                package.transactions.len(),
                self.max_package_count
            );
        }
        
        // Check package size
        if package.total_size > self.max_package_size {
            bail!(
                "Package size {} bytes exceeds limit of {} bytes",
                package.total_size,
                self.max_package_size
            );
        }
        
        // Check package weight
        if package.total_weight > self.max_package_weight {
            bail!(
                "Package weight {} exceeds limit of {}",
                package.total_weight,
                self.max_package_weight
            );
        }
        
        // Check minimum fee rate
        if package.package_feerate < self.min_package_feerate {
            bail!(
                "Package fee rate {:.2} sat/vB below minimum {:.2} sat/vB",
                package.package_feerate,
                self.min_package_feerate
            );
        }
        
        // Check for conflicts within package
        package.check_conflicts()?;
        
        // Verify topological ordering
        self.verify_topological_order(package)?;
        
        Ok(())
    }
    
    /// Verify transactions are in topological order
    fn verify_topological_order(&self, package: &Package) -> Result<()> {
        let mut seen = HashSet::new();
        
        for tx in &package.transactions {
            let txid = tx.compute_txid();
            
            // Check that all parent transactions come before this one
            for input in &tx.input {
                let parent_txid = input.previous_output.txid;
                
                // Skip if parent is not in the package
                if !package.txids.contains(&parent_txid) {
                    continue;
                }
                
                // Parent must have been seen already
                if !seen.contains(&parent_txid) {
                    bail!(
                        "Package not in topological order: {} depends on {} which comes later",
                        txid,
                        parent_txid
                    );
                }
            }
            
            seen.insert(txid);
        }
        
        Ok(())
    }
    
    /// Check if package can replace existing mempool transactions
    pub async fn check_package_rbf(
        &self,
        package: &Package,
        conflicts: &[Transaction],
        rbf_policy: &RBFPolicy,
    ) -> Result<bool> {
        if conflicts.is_empty() {
            return Ok(true);
        }
        
        info!(
            "Checking package RBF: {} transactions replacing {} conflicts",
            package.transactions.len(),
            conflicts.len()
        );
        
        // For package RBF, we treat the entire package as a single replacement
        // The package must pay higher fees than all conflicting transactions combined
        
        // Calculate total fee of conflicting transactions
        let mut conflict_fee = Amount::ZERO;
        let mut conflict_size = 0usize;
        
        for tx in conflicts {
            // Would need UTXO provider to calculate actual fees
            // For now, use a placeholder
            conflict_size += bitcoin::consensus::serialize(tx).len();
        }
        
        // Package must pay more in total fees
        if package.total_fee <= conflict_fee {
            bail!(
                "Package fee {} must exceed conflicting transactions fee {}",
                package.total_fee,
                conflict_fee
            );
        }
        
        // Package must have higher fee rate
        let conflict_feerate = if conflict_size > 0 {
            (conflict_fee.to_sat() as f64) / (conflict_size as f64)
        } else {
            0.0
        };
        
        if package.package_feerate <= conflict_feerate {
            bail!(
                "Package fee rate {:.2} must exceed conflicts rate {:.2}",
                package.package_feerate,
                conflict_feerate
            );
        }
        
        Ok(true)
    }
}

/// Package acceptance result
#[derive(Debug)]
pub enum PackageAcceptanceResult {
    /// All transactions accepted
    AllAccepted {
        txids: Vec<Txid>,
        total_fee: Amount,
        total_size: usize,
    },
    
    /// Some transactions accepted
    PartiallyAccepted {
        accepted: Vec<Txid>,
        rejected: Vec<(Txid, String)>,
    },
    
    /// All transactions rejected
    AllRejected {
        reasons: Vec<(Txid, String)>,
    },
}

/// Package relay manager for coordinating package acceptance
pub struct PackageRelayManager {
    /// Package validator
    validator: PackageValidator,
    
    /// Pending packages awaiting acceptance
    pending_packages: HashMap<Vec<Txid>, Package>,
    
    /// Orphan transactions waiting for parents
    orphan_pool: HashMap<Txid, Transaction>,
    
    /// Map from missing parent to orphans waiting for it
    orphan_deps: HashMap<Txid, HashSet<Txid>>,
}

impl PackageRelayManager {
    pub fn new(validator: PackageValidator) -> Self {
        Self {
            validator,
            pending_packages: HashMap::new(),
            orphan_pool: HashMap::new(),
            orphan_deps: HashMap::new(),
        }
    }
    
    /// Add an orphan transaction
    pub fn add_orphan(&mut self, tx: Transaction, missing_parents: Vec<Txid>) {
        let txid = tx.compute_txid();
        
        debug!(
            "Adding orphan {} with {} missing parents",
            txid,
            missing_parents.len()
        );
        
        self.orphan_pool.insert(txid, tx);
        
        for parent in missing_parents {
            self.orphan_deps.entry(parent).or_default().insert(txid);
        }
    }
    
    /// Try to resolve orphans when a new transaction arrives
    pub fn resolve_orphans(&mut self, parent_txid: Txid) -> Vec<Transaction> {
        let mut resolved = Vec::new();
        
        if let Some(orphan_txids) = self.orphan_deps.remove(&parent_txid) {
            for orphan_txid in orphan_txids {
                if let Some(orphan_tx) = self.orphan_pool.remove(&orphan_txid) {
                    debug!("Resolved orphan {} with parent {}", orphan_txid, parent_txid);
                    resolved.push(orphan_tx);
                }
            }
        }
        
        resolved
    }
    
    /// Create a package from a child and its unconfirmed parents
    pub fn create_child_with_parents_package(
        &self,
        child: Transaction,
        parents: Vec<Transaction>,
    ) -> Result<Package> {
        let mut transactions = parents;
        transactions.push(child);
        
        let mut package = Package::new(transactions, PackageType::ChildWithParents)?;
        package.topological_sort()?;
        
        Ok(package)
    }
}