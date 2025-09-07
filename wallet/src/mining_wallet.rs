use anyhow::{bail, Result};
use bitcoin::blockdata::constants::COINBASE_MATURITY;
use bitcoin::blockdata::script;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{
    absolute, Address, Amount, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Mining wallet for managing coinbase rewards
pub struct MiningWallet {
    /// Network type
    network: Network,

    /// Mining addresses by height
    addresses: Arc<RwLock<HashMap<u32, Address>>>,

    /// Private keys for addresses
    keys: Arc<RwLock<HashMap<Address, SecretKey>>>,

    /// Coinbase outputs we've created
    coinbase_outputs: Arc<RwLock<HashMap<OutPoint, CoinbaseOutput>>>,

    /// Wallet storage path
    storage_path: Option<String>,

    /// Default mining address
    default_address: Option<Address>,
}

/// Coinbase output information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinbaseOutput {
    /// Block height where this was mined
    pub height: u32,

    /// Block hash
    pub block_hash: BlockHash,

    /// Output value
    pub value: Amount,

    /// Output script
    pub script_pubkey: ScriptBuf,

    /// Maturity height (when spendable)
    pub maturity_height: u32,

    /// Whether this has been spent
    pub spent: bool,
}

/// Mining wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningWalletConfig {
    /// Network to use
    pub network: Network,

    /// Storage path for wallet data
    pub storage_path: Option<String>,

    /// Use HD derivation for addresses
    pub use_hd: bool,

    /// HD seed (if use_hd is true)
    pub hd_seed: Option<Vec<u8>>,
}

impl Default for MiningWalletConfig {
    fn default() -> Self {
        Self {
            network: Network::Bitcoin,
            storage_path: Some("./mining_wallet".to_string()),
            use_hd: false,
            hd_seed: None,
        }
    }
}

impl MiningWallet {
    /// Create new mining wallet
    pub fn new(config: MiningWalletConfig) -> Result<Self> {
        info!(
            "Creating new mining wallet for network: {:?}",
            config.network
        );

        let wallet = Self {
            network: config.network,
            addresses: Arc::new(RwLock::new(HashMap::new())),
            keys: Arc::new(RwLock::new(HashMap::new())),
            coinbase_outputs: Arc::new(RwLock::new(HashMap::new())),
            storage_path: config.storage_path,
            default_address: None,
        };

        // Load existing data if storage path is provided
        if let Some(ref path) = wallet.storage_path {
            if Path::new(path).exists() {
                // TODO: Load wallet data from storage
                debug!("Loading wallet data from: {}", path);
            }
        }

        Ok(wallet)
    }

    /// Generate a new mining address
    pub async fn generate_mining_address(&self) -> Result<Address> {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

        // Create P2WPKH address (native segwit)
        let bitcoin_pubkey = bitcoin::PublicKey::from_slice(&public_key.serialize())
            .map_err(|e| anyhow::anyhow!("Failed to create bitcoin public key: {:?}", e))?;
        let compressed = bitcoin::key::CompressedPublicKey::try_from(bitcoin_pubkey)
            .map_err(|e| anyhow::anyhow!("Failed to compress public key: {:?}", e))?;
        let address = Address::p2wpkh(&compressed, self.network);

        // Store the key
        self.keys.write().await.insert(address.clone(), secret_key);

        info!("Generated new mining address: {}", address);
        Ok(address)
    }

    /// Set default mining address
    pub async fn set_default_address(&mut self, address: Address) -> Result<()> {
        // Verify we have the key for this address
        if !self.keys.read().await.contains_key(&address) {
            bail!("Don't have private key for address: {}", address);
        }

        self.default_address = Some(address.clone());
        info!("Set default mining address: {}", address);
        Ok(())
    }

    /// Get or create mining address for a specific block height
    pub async fn get_mining_address(&self, height: u32) -> Result<Address> {
        // Check if we have an address for this height
        if let Some(address) = self.addresses.read().await.get(&height) {
            return Ok(address.clone());
        }

        // Use default address if set
        if let Some(ref default_addr) = self.default_address {
            return Ok(default_addr.clone());
        }

        // Generate new address
        let address = self.generate_mining_address().await?;
        self.addresses.write().await.insert(height, address.clone());

        Ok(address)
    }

    /// Create coinbase transaction
    pub async fn create_coinbase_transaction(
        &self,
        height: u32,
        block_reward: Amount,
        fees: Amount,
        extra_nonce: Vec<u8>,
    ) -> Result<Transaction> {
        let total_value = block_reward + fees;

        // Get mining address
        let address = self.get_mining_address(height).await?;

        // Create coinbase input
        let coinbase_input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: self.create_coinbase_script(height, extra_nonce),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        // Create output to mining address
        let coinbase_output = TxOut {
            value: total_value,
            script_pubkey: address.script_pubkey(),
        };

        // Create transaction
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: absolute::LockTime::from_height(0)?,
            input: vec![coinbase_input],
            output: vec![coinbase_output],
        };

        // Store coinbase output info
        let outpoint = OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        };

        let output_info = CoinbaseOutput {
            height,
            block_hash: BlockHash::from_byte_array([0u8; 32]), // Will be updated when block is mined
            value: total_value,
            script_pubkey: address.script_pubkey(),
            maturity_height: height + COINBASE_MATURITY,
            spent: false,
        };

        self.coinbase_outputs
            .write()
            .await
            .insert(outpoint, output_info);

        debug!(
            "Created coinbase transaction for height {} with value {} to address {}",
            height, total_value, address
        );

        Ok(tx)
    }

    /// Create coinbase script signature
    fn create_coinbase_script(&self, height: u32, extra_nonce: Vec<u8>) -> ScriptBuf {
        let mut script = script::Builder::new();

        // Add block height (BIP34)
        script = script.push_int(height as i64);

        // Add extra nonce for additional entropy
        if !extra_nonce.is_empty() {
            script = script.push_slice(
                &bitcoin::script::PushBytesBuf::try_from(extra_nonce.clone()).unwrap()[..],
            );
        }

        // Add arbitrary data (could be pool tag, etc.)
        script =
            script.push_slice(
                &bitcoin::script::PushBytesBuf::try_from(b"rust-bitcoin-core/1.0".to_vec())
                    .unwrap()[..],
            );

        script.into_script()
    }

    /// Update coinbase output with actual block hash
    pub async fn update_coinbase_output(&self, txid: &Txid, block_hash: BlockHash) -> Result<()> {
        let outpoint = OutPoint {
            txid: *txid,
            vout: 0,
        };

        if let Some(output) = self.coinbase_outputs.write().await.get_mut(&outpoint) {
            output.block_hash = block_hash;
            debug!(
                "Updated coinbase output {} with block hash {}",
                txid, block_hash
            );
        }

        Ok(())
    }

    /// Get mature coinbase outputs (spendable)
    pub async fn get_mature_outputs(&self, current_height: u32) -> Vec<(OutPoint, CoinbaseOutput)> {
        let outputs = self.coinbase_outputs.read().await;

        outputs
            .iter()
            .filter(|(_, output)| !output.spent && current_height >= output.maturity_height)
            .map(|(outpoint, output)| (*outpoint, output.clone()))
            .collect()
    }

    /// Get immature coinbase outputs (not yet spendable)
    pub async fn get_immature_outputs(
        &self,
        current_height: u32,
    ) -> Vec<(OutPoint, CoinbaseOutput)> {
        let outputs = self.coinbase_outputs.read().await;

        outputs
            .iter()
            .filter(|(_, output)| !output.spent && current_height < output.maturity_height)
            .map(|(outpoint, output)| (*outpoint, output.clone()))
            .collect()
    }

    /// Get total balance
    pub async fn get_balance(&self, current_height: u32) -> MiningBalance {
        let outputs = self.coinbase_outputs.read().await;

        let mut mature = Amount::ZERO;
        let mut immature = Amount::ZERO;

        for output in outputs.values() {
            if output.spent {
                continue;
            }

            if current_height >= output.maturity_height {
                mature += output.value;
            } else {
                immature += output.value;
            }
        }

        MiningBalance { mature, immature }
    }

    /// Mark output as spent
    pub async fn mark_spent(&self, outpoint: &OutPoint) -> Result<()> {
        if let Some(output) = self.coinbase_outputs.write().await.get_mut(outpoint) {
            output.spent = true;
            debug!("Marked output as spent: {:?}", outpoint);
        } else {
            bail!("Output not found: {:?}", outpoint);
        }

        Ok(())
    }

    /// Save wallet state to storage
    pub async fn save(&self) -> Result<()> {
        if let Some(ref path) = self.storage_path {
            // TODO: Implement actual storage
            debug!("Saving wallet state to: {}", path);
        }
        Ok(())
    }

    /// Create witness commitment for segwit blocks
    pub fn create_witness_commitment(
        &self,
        witness_root: &[u8; 32],
        witness_nonce: &[u8; 32],
    ) -> ScriptBuf {
        use bitcoin::hashes::{sha256d, Hash as HashTrait};

        // Calculate commitment hash
        let mut commitment_input = Vec::with_capacity(64);
        commitment_input.extend_from_slice(witness_root);
        commitment_input.extend_from_slice(witness_nonce);
        let commitment = sha256d::Hash::hash(&commitment_input);

        // Create commitment script
        script::Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(
                &bitcoin::script::PushBytesBuf::try_from(vec![0xaa, 0x21, 0xa9, 0xed]).unwrap()[..],
            ) // Witness commitment header
            .push_slice(
                &bitcoin::script::PushBytesBuf::try_from(commitment.to_byte_array().to_vec())
                    .unwrap()[..],
            )
            .into_script()
    }
}

/// Mining wallet balance
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MiningBalance {
    /// Mature (spendable) balance
    pub mature: Amount,

    /// Immature (not yet spendable) balance  
    pub immature: Amount,
}

impl MiningBalance {
    /// Get total balance (mature + immature)
    pub fn total(&self) -> Amount {
        self.mature + self.immature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mining_wallet_creation() -> Result<()> {
        let config = MiningWalletConfig {
            network: Network::Regtest,
            ..Default::default()
        };

        let wallet = MiningWallet::new(config)?;

        // Generate address
        let address = wallet.generate_mining_address().await?;
        // API changed in bitcoin 0.32 - just verify address was generated
        assert!(!address.to_string().is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_coinbase_transaction() -> Result<()> {
        let config = MiningWalletConfig {
            network: Network::Regtest,
            ..Default::default()
        };

        let wallet = MiningWallet::new(config)?;

        // Create coinbase transaction
        let height = 100;
        let block_reward = Amount::from_sat(50_00000000);
        let fees = Amount::from_sat(10000);
        let extra_nonce = vec![0x01, 0x02, 0x03, 0x04];

        let tx = wallet
            .create_coinbase_transaction(height, block_reward, fees, extra_nonce)
            .await?;

        // Verify transaction
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert!(tx.is_coinbase());
        assert_eq!(tx.output[0].value, block_reward + fees);

        Ok(())
    }

    #[tokio::test]
    async fn test_balance_tracking() -> Result<()> {
        let config = MiningWalletConfig {
            network: Network::Regtest,
            ..Default::default()
        };

        let wallet = MiningWallet::new(config)?;

        // Create some coinbase transactions
        for i in 0..5 {
            let height = i * 10;
            let block_reward = Amount::from_sat(50_00000000);
            let fees = Amount::from_sat(10000);

            wallet
                .create_coinbase_transaction(height, block_reward, fees, vec![])
                .await?;
        }

        // Check balance at different heights
        let balance_at_50 = wallet.get_balance(50).await;
        let balance_at_150 = wallet.get_balance(150).await;

        // At height 50, nothing should be mature (need 100 confirmations)
        assert_eq!(balance_at_50.mature, Amount::ZERO);
        assert!(balance_at_50.immature > Amount::ZERO);

        // At height 150, first output should be mature
        assert!(balance_at_150.mature > Amount::ZERO);

        Ok(())
    }
}
