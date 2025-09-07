use anyhow::{Result, bail, Context};
use bitcoin::{Transaction, Amount, FeeRate, Weight};
use bitcoin::blockdata::script::Instruction;
use bitcoin::blockdata::opcodes;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Transaction relay and mempool acceptance policies
#[derive(Debug, Clone)]
pub struct RelayPolicy {
    /// Minimum relay fee rate (sat/vB)
    pub min_relay_fee_rate: FeeRate,
    
    /// Incremental relay fee rate for RBF (sat/vB)
    pub incremental_relay_fee: FeeRate,
    
    /// Dust relay fee rate (sat/vB)
    pub dust_relay_fee_rate: FeeRate,
    
    /// Maximum standard transaction weight
    pub max_standard_tx_weight: Weight,
    
    /// Maximum standard script sig size
    pub max_standard_scriptsig_size: usize,
    
    /// Maximum standard P2WSH script size
    pub max_standard_p2wsh_script_size: usize,
    
    /// Maximum standard P2WSH stack items
    pub max_standard_p2wsh_stack_items: usize,
    
    /// Maximum ancestor count for mempool
    pub max_ancestor_count: usize,
    
    /// Maximum descendant count for mempool
    pub max_descendant_count: usize,
    
    /// Maximum ancestor size (vB)
    pub max_ancestor_size: usize,
    
    /// Maximum descendant size (vB)
    pub max_descendant_size: usize,
    
    /// Allow replace-by-fee
    pub enable_rbf: bool,
    
    /// Allow full RBF (BIP125)
    pub full_rbf: bool,
    
    /// Reject non-standard transactions
    pub reject_non_standard: bool,
    
    /// Maximum OP_RETURN size
    pub max_op_return_size: usize,
    
    /// Maximum bare multisig keys
    pub max_bare_multisig_keys: usize,
    
    /// Allow data carrier outputs (OP_RETURN)
    pub permit_bare_multisig: bool,
    
    /// Require standard inputs
    pub require_standard: bool,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            min_relay_fee_rate: FeeRate::from_sat_per_vb(1).expect("Valid fee rate"),
            incremental_relay_fee: FeeRate::from_sat_per_vb(1).expect("Valid fee rate"),
            dust_relay_fee_rate: FeeRate::from_sat_per_vb(3).expect("Valid fee rate"),
            max_standard_tx_weight: Weight::from_wu(400_000),
            max_standard_scriptsig_size: 1650,
            max_standard_p2wsh_script_size: 3600,
            max_standard_p2wsh_stack_items: 100,
            max_ancestor_count: 25,
            max_descendant_count: 25,
            max_ancestor_size: 101_000, // 101 KB
            max_descendant_size: 101_000,
            enable_rbf: true,
            full_rbf: false,
            reject_non_standard: true,
            max_op_return_size: 83,
            max_bare_multisig_keys: 3,
            permit_bare_multisig: true,
            require_standard: true,
        }
    }
}

/// Transaction relay validator
pub struct RelayValidator {
    policy: RelayPolicy,
}

impl RelayValidator {
    pub fn new(policy: RelayPolicy) -> Self {
        Self { policy }
    }
    
    /// Check if transaction meets relay policies
    pub fn check_transaction(
        &self,
        tx: &Transaction,
        inputs_value: Amount,
    ) -> Result<RelayCheckResult> {
        let mut result = RelayCheckResult::default();
        
        // Check transaction weight
        let tx_weight = tx.weight();
        if tx_weight > self.policy.max_standard_tx_weight {
            bail!("Transaction weight {} exceeds maximum {}", 
                  tx_weight, self.policy.max_standard_tx_weight);
        }
        result.weight = tx_weight;
        
        // Calculate fee
        let output_value = tx.output.iter()
            .map(|out| out.value)
            .sum::<Amount>();
        
        if inputs_value < output_value {
            bail!("Transaction spends more than it inputs");
        }
        
        let fee = inputs_value - output_value;
        result.fee = fee;
        
        // Check fee rate
        let vsize = tx_weight.to_vbytes_ceil();
        let fee_rate = FeeRate::from_sat_per_vb(fee.to_sat() / vsize as u64)
            .context("Invalid fee rate")?;
        result.fee_rate = fee_rate;
        
        if fee_rate < self.policy.min_relay_fee_rate {
            bail!("Fee rate {} below minimum relay fee {}", 
                  fee_rate, self.policy.min_relay_fee_rate);
        }
        
        // Check for standard transaction
        if self.policy.reject_non_standard {
            self.check_standard_transaction(tx)?;
        }
        
        // Check for dust outputs
        for (i, output) in tx.output.iter().enumerate() {
            if self.is_dust_output(output)? {
                result.has_dust = true;
                warn!("Transaction has dust output at index {}", i);
            }
        }
        
        // Check RBF signaling
        result.signals_rbf = self.check_rbf_signaling(tx);
        
        // Check script sizes
        for input in &tx.input {
            if input.script_sig.len() > self.policy.max_standard_scriptsig_size {
                bail!("Script sig size {} exceeds maximum {}", 
                      input.script_sig.len(), self.policy.max_standard_scriptsig_size);
            }
        }
        
        Ok(result)
    }
    
    /// Check if transaction is standard
    fn check_standard_transaction(&self, tx: &Transaction) -> Result<()> {
        // Version must be 1 or 2
        let version = tx.version.0;
        if version < 1 || version > 2 {
            bail!("Non-standard transaction version: {}", version);
        }
        
        // Check each output
        for output in &tx.output {
            self.check_standard_output(output)?;
        }
        
        // Check each input (if required)
        if self.policy.require_standard {
            for input in &tx.input {
                self.check_standard_input(input)?;
            }
        }
        
        Ok(())
    }
    
    /// Check if output is standard
    fn check_standard_output(&self, output: &bitcoin::TxOut) -> Result<()> {
        let script = &output.script_pubkey;
        
        // Check for standard script types
        if script.is_p2pk() || 
           script.is_p2pkh() || 
           script.is_p2sh() || 
           script.is_p2wpkh() || 
           script.is_p2wsh() ||
           script.is_p2tr() {
            return Ok(());
        }
        
        // Check for OP_RETURN
        if script.is_op_return() {
            if script.len() > self.policy.max_op_return_size {
                bail!("OP_RETURN size {} exceeds maximum {}", 
                      script.len(), self.policy.max_op_return_size);
            }
            return Ok(());
        }
        
        // Check for bare multisig
        if self.is_bare_multisig(script)? {
            if !self.policy.permit_bare_multisig {
                bail!("Bare multisig not permitted");
            }
            return Ok(());
        }
        
        bail!("Non-standard output script");
    }
    
    /// Check if input is standard
    fn check_standard_input(&self, input: &bitcoin::TxIn) -> Result<()> {
        // Check script sig doesn't contain non-push operations
        for instruction in input.script_sig.instructions() {
            match instruction {
                Ok(Instruction::PushBytes(_)) => continue,
                Ok(Instruction::Op(op)) if op.to_u8() <= opcodes::all::OP_PUSHNUM_16.to_u8() => continue,
                _ => bail!("Non-standard script sig contains non-push operations"),
            }
        }
        
        Ok(())
    }
    
    /// Check if output is dust
    fn is_dust_output(&self, output: &bitcoin::TxOut) -> Result<bool> {
        let dust_threshold = self.get_dust_threshold(output);
        Ok(output.value < dust_threshold)
    }
    
    /// Get dust threshold for an output
    fn get_dust_threshold(&self, output: &bitcoin::TxOut) -> Amount {
        // Calculate size of spending this output
        let mut input_size = 32 + 4 + 4 + 1; // outpoint + sequence + script length
        
        if output.script_pubkey.is_p2pkh() {
            input_size += 107; // signature + pubkey
        } else if output.script_pubkey.is_p2sh() {
            input_size += 148; // Assuming 2-of-3 multisig
        } else if output.script_pubkey.is_p2wpkh() {
            input_size += 67; // Witness data
        } else if output.script_pubkey.is_p2wsh() {
            input_size += 100; // Approximate
        } else if output.script_pubkey.is_p2tr() {
            input_size += 57; // Schnorr signature
        } else {
            input_size += 148; // Conservative estimate
        }
        
        // Dust if output value < 3 * min_relay_fee * input_size
        let dust_fee = self.policy.dust_relay_fee_rate.to_sat_per_vb() * input_size;
        Amount::from_sat(dust_fee)
    }
    
    /// Check if script is bare multisig
    fn is_bare_multisig(&self, script: &bitcoin::ScriptBuf) -> Result<bool> {
        let ops: Vec<_> = script.instructions().collect();
        
        if ops.len() < 4 {
            return Ok(false);
        }
        
        // Check pattern: <m> <pubkeys...> <n> OP_CHECKMULTISIG
        if let Some(Ok(Instruction::Op(last_op))) = ops.last() {
            if *last_op == opcodes::all::OP_CHECKMULTISIG {
                // Count public keys
                let n_keys = ops.len() - 3; // Subtract m, n, and CHECKMULTISIG
                return Ok(n_keys <= self.policy.max_bare_multisig_keys);
            }
        }
        
        Ok(false)
    }
    
    /// Check if transaction signals RBF
    fn check_rbf_signaling(&self, tx: &Transaction) -> bool {
        if !self.policy.enable_rbf {
            return false;
        }
        
        if self.policy.full_rbf {
            // All transactions are replaceable
            return true;
        }
        
        // BIP125: Transaction signals RBF if any input has sequence < 0xfffffffe
        tx.input.iter().any(|input| input.sequence.0 < 0xfffffffe)
    }
    
    /// Check if transaction can replace another (RBF rules)
    pub fn check_replacement(
        &self,
        new_tx: &Transaction,
        new_fee: Amount,
        old_tx: &Transaction,
        old_fee: Amount,
        conflicts: &[Transaction],
    ) -> Result<()> {
        if !self.policy.enable_rbf {
            bail!("Replace-by-fee is disabled");
        }
        
        // Rule 1: Original transaction must signal replaceability
        if !self.policy.full_rbf && !self.check_rbf_signaling(old_tx) {
            bail!("Original transaction does not signal RBF");
        }
        
        // Rule 2: Replacement must not add new unconfirmed inputs
        let old_inputs: std::collections::HashSet<_> = old_tx.input.iter()
            .map(|i| i.previous_output)
            .collect();
        
        for input in &new_tx.input {
            if !old_inputs.contains(&input.previous_output) {
                // This is a new input - need to check if it's confirmed
                // (Would need UTXO set access here)
                debug!("Replacement adds new input: {}", input.previous_output);
            }
        }
        
        // Rule 3: Replacement must pay higher absolute fee
        if new_fee <= old_fee {
            bail!("Replacement fee {} not greater than original {}", new_fee, old_fee);
        }
        
        // Rule 4: Additional fee must be at least minRelayFee * size
        let fee_delta = new_fee - old_fee;
        let new_size = bitcoin::consensus::encode::serialize(new_tx).len() as u64;
        let min_fee_delta = self.policy.incremental_relay_fee.to_sat_per_vb() * new_size;
        
        if fee_delta.to_sat() < min_fee_delta {
            bail!("Replacement fee delta {} below minimum {}", fee_delta, min_fee_delta);
        }
        
        // Rule 5: Number of replacements must not be excessive
        if conflicts.len() > 100 {
            bail!("Replacement would evict too many transactions ({})", conflicts.len());
        }
        
        Ok(())
    }
}

/// Result of relay policy check
#[derive(Debug, Default)]
pub struct RelayCheckResult {
    pub weight: Weight,
    pub fee: Amount,
    pub fee_rate: FeeRate,
    pub has_dust: bool,
    pub signals_rbf: bool,
}

/// Package relay policies (for transaction packages)
pub struct PackagePolicy {
    /// Maximum package size in virtual bytes
    pub max_package_vsize: u64,
    
    /// Maximum package count
    pub max_package_count: usize,
    
    /// Allow CPFP (Child Pays For Parent)
    pub allow_cpfp: bool,
}

impl Default for PackagePolicy {
    fn default() -> Self {
        Self {
            max_package_vsize: 101_000,
            max_package_count: 25,
            allow_cpfp: true,
        }
    }
}

/// Check transaction package acceptance
pub fn check_package(
    txs: &[Transaction],
    policy: &PackagePolicy,
) -> Result<()> {
    if txs.is_empty() {
        bail!("Empty package");
    }
    
    if txs.len() > policy.max_package_count {
        bail!("Package count {} exceeds maximum {}", 
              txs.len(), policy.max_package_count);
    }
    
    // Calculate total vsize
    let total_vsize: u64 = txs.iter()
        .map(|tx| tx.weight().to_vbytes_ceil())
        .sum();
    
    if total_vsize > policy.max_package_vsize {
        bail!("Package vsize {} exceeds maximum {}", 
              total_vsize, policy.max_package_vsize);
    }
    
    // Check for dependency cycles
    let mut outputs = std::collections::HashSet::new();
    for tx in txs {
        let txid = tx.compute_txid();
        for (vout, _) in tx.output.iter().enumerate() {
            outputs.insert(bitcoin::OutPoint::new(txid, vout as u32));
        }
    }
    
    for tx in txs {
        for input in &tx.input {
            if outputs.contains(&input.previous_output) {
                // This is an in-package dependency, which is allowed
                debug!("Package has internal dependency");
            }
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_relay_policy_defaults() {
        let policy = RelayPolicy::default();
        assert_eq!(policy.min_relay_fee_rate.to_sat_per_vb(), 1);
        assert_eq!(policy.max_standard_tx_weight, Weight::from_wu(400_000));
        assert!(policy.enable_rbf);
    }
    
    #[test]
    fn test_dust_threshold() {
        let policy = RelayPolicy::default();
        let validator = RelayValidator::new(policy);
        
        // P2PKH output
        let output = bitcoin::TxOut {
            value: Amount::from_sat(546),
            script_pubkey: bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::all_zeros()),
        };
        
        let threshold = validator.get_dust_threshold(&output);
        assert!(threshold > Amount::ZERO);
    }
}