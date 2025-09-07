use bitcoin::bip32::DerivationPath;
use bitcoin::key::CompressedPublicKey;
use bitcoin::{Address, PublicKey};
use std::collections::HashMap;
use std::hash::Hash;
use tracing::{debug, info};

use crate::error::{WalletError, WalletResult};
use crate::keychain::KeyChain;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// P2WPKH - Native SegWit (bc1...)
    P2wpkh,
    /// P2SH-P2WPKH - Nested SegWit (3...)
    P2shwpkh,
    /// P2PKH - Legacy (1...)
    P2pkh,
    // Aliases for compatibility
    NativeSegwit,
    NestedSegwit,
    Legacy,
}

/// Address metadata
#[derive(Debug, Clone)]
pub struct AddressInfo {
    pub address: Address,
    pub derivation_path: String,
    pub address_type: AddressType,
    pub index: u32,
    pub change: bool,
    pub used: bool,
}

/// Address manager for HD wallet
pub struct AddressManager {
    keychain: KeyChain,
    addresses: HashMap<String, AddressInfo>,
    next_index: HashMap<(AddressType, bool), u32>, // (type, is_change) -> next_index
    gap_limit: u32,
}

impl AddressManager {
    /// Create a new address manager
    pub fn new(keychain: KeyChain) -> Self {
        Self {
            keychain,
            addresses: HashMap::new(),
            next_index: HashMap::new(),
            gap_limit: 20, // Standard gap limit
        }
    }

    /// Generate a new receive address
    pub fn new_receive_address(&mut self, address_type: AddressType) -> WalletResult<Address> {
        self.new_address(address_type, false)
    }

    /// Generate a new change address
    pub fn new_change_address(&mut self, address_type: AddressType) -> WalletResult<Address> {
        self.new_address(address_type, true)
    }

    /// Get a receive address at a specific index
    pub fn get_receive_address_at_index(
        &self,
        address_type: AddressType,
        index: u32,
    ) -> WalletResult<Address> {
        let change_idx = 0; // receive

        let path = match address_type {
            AddressType::P2wpkh | AddressType::NativeSegwit => {
                KeyChain::bip84_path(0, change_idx, index)?
            }
            AddressType::P2shwpkh | AddressType::NestedSegwit => {
                KeyChain::bip49_path(0, change_idx, index)?
            }
            AddressType::P2pkh | AddressType::Legacy => KeyChain::bip44_path(0, change_idx, index)?,
        };

        self.derive_address(&path, address_type)
    }

    /// Get a change address at a specific index
    pub fn get_change_address_at_index(
        &self,
        address_type: AddressType,
        index: u32,
    ) -> WalletResult<Address> {
        let change_idx = 1; // change

        let path = match address_type {
            AddressType::P2wpkh | AddressType::NativeSegwit => {
                KeyChain::bip84_path(0, change_idx, index)?
            }
            AddressType::P2shwpkh | AddressType::NestedSegwit => {
                KeyChain::bip49_path(0, change_idx, index)?
            }
            AddressType::P2pkh | AddressType::Legacy => KeyChain::bip44_path(0, change_idx, index)?,
        };

        self.derive_address(&path, address_type)
    }

    /// Generate a new address
    fn new_address(&mut self, address_type: AddressType, change: bool) -> WalletResult<Address> {
        let change_idx = if change { 1 } else { 0 };
        let key = (address_type, change);
        let index = *self.next_index.entry(key).or_insert(0);

        let path = match address_type {
            AddressType::P2wpkh | AddressType::NativeSegwit => {
                KeyChain::bip84_path(0, change_idx, index)?
            }
            AddressType::P2shwpkh | AddressType::NestedSegwit => {
                KeyChain::bip49_path(0, change_idx, index)?
            }
            AddressType::P2pkh | AddressType::Legacy => KeyChain::bip44_path(0, change_idx, index)?,
        };

        let address = self.derive_address(&path, address_type)?;

        // Store address info
        let info = AddressInfo {
            address: address.clone(),
            derivation_path: format!("{:?}", path),
            address_type,
            index,
            change,
            used: false,
        };

        self.addresses.insert(address.to_string(), info);

        // Increment index for next address
        self.next_index.insert(key, index + 1);

        info!(
            "Generated new {} address at index {}: {}",
            if change { "change" } else { "receive" },
            index,
            address
        );

        Ok(address)
    }

    /// Derive an address at a specific path
    fn derive_address(
        &self,
        path: &DerivationPath,
        address_type: AddressType,
    ) -> WalletResult<Address> {
        let xpub = self.keychain.derive_public_key(path)?;

        // Convert to bitcoin PublicKey
        let pubkey = PublicKey::new(xpub.public_key);
        // Convert to compressed format
        let compressed = CompressedPublicKey::try_from(pubkey).map_err(|e| {
            WalletError::Other(anyhow::anyhow!("Failed to compress pubkey: {:?}", e))
        })?;

        let address = match address_type {
            AddressType::P2wpkh | AddressType::NativeSegwit => {
                // P2WPKH
                Address::p2wpkh(&compressed, self.keychain.network())
            }
            AddressType::P2shwpkh | AddressType::NestedSegwit => {
                // P2SH-P2WPKH
                Address::p2shwpkh(&compressed, self.keychain.network())
            }
            AddressType::P2pkh | AddressType::Legacy => {
                // P2PKH
                Address::p2pkh(compressed, self.keychain.network())
            }
        };

        Ok(address)
    }

    /// Mark an address as used
    pub fn mark_used(&mut self, address: &str) -> WalletResult<()> {
        if let Some(info) = self.addresses.get_mut(address) {
            info.used = true;
            debug!("Marked address {} as used", address);
            Ok(())
        } else {
            Err(WalletError::Other(anyhow::anyhow!("Address not found")))
        }
    }

    /// Get all addresses
    pub fn get_all_addresses(&self) -> Vec<&AddressInfo> {
        self.addresses.values().collect()
    }

    /// Get unused addresses
    pub fn get_unused_addresses(&self) -> Vec<&AddressInfo> {
        self.addresses.values().filter(|info| !info.used).collect()
    }

    /// Check if an address belongs to this wallet
    pub fn is_mine(&self, address: &str) -> bool {
        self.addresses.contains_key(address)
    }

    /// Restore an address from storage
    pub fn restore_address(
        &mut self,
        address: String,
        path: String,
        address_type: AddressType,
        index: u32,
        change: bool,
        used: bool,
    ) -> WalletResult<()> {
        use std::str::FromStr;

        // Parse the address
        let addr = bitcoin::Address::from_str(&address)
            .map_err(|e| WalletError::Other(anyhow::anyhow!("Invalid address: {}", e)))?
            .assume_checked();

        let info = AddressInfo {
            address: addr,
            derivation_path: path,
            address_type,
            index,
            change,
            used,
        };

        // Update next_index if necessary
        let key = (address_type, change);
        let current_next = self.next_index.entry(key).or_insert(0);
        if index >= *current_next {
            *current_next = index + 1;
        }

        self.addresses.insert(address.clone(), info);
        debug!("Restored address {} at index {}", address, index);

        Ok(())
    }

    /// Scan for gap limit and generate addresses as needed
    pub fn scan_gap_limit(&mut self, address_type: AddressType) -> WalletResult<()> {
        // Generate addresses for both receive and change
        for change in [false, true] {
            let mut consecutive_unused = 0;
            let mut index = 0;

            while consecutive_unused < self.gap_limit {
                let change_idx = if change { 1 } else { 0 };

                let path = match address_type {
                    AddressType::P2wpkh | AddressType::NativeSegwit => {
                        KeyChain::bip84_path(0, change_idx, index)?
                    }
                    AddressType::P2shwpkh | AddressType::NestedSegwit => {
                        KeyChain::bip49_path(0, change_idx, index)?
                    }
                    AddressType::P2pkh | AddressType::Legacy => {
                        KeyChain::bip44_path(0, change_idx, index)?
                    }
                };

                let address = self.derive_address(&path, address_type)?;
                let address_str = address.to_string();

                // Check if address is already known
                if let Some(info) = self.addresses.get(&address_str) {
                    if info.used {
                        consecutive_unused = 0;
                    } else {
                        consecutive_unused += 1;
                    }
                } else {
                    // Add new address
                    let info = AddressInfo {
                        address,
                        derivation_path: format!("{:?}", path),
                        address_type,
                        index,
                        change,
                        used: false,
                    };

                    self.addresses.insert(address_str, info);
                    consecutive_unused += 1;
                }

                index += 1;
            }

            // Update next index
            self.next_index
                .insert((address_type, change), index - self.gap_limit);
        }

        Ok(())
    }
}
