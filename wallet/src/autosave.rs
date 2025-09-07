use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info};

use crate::wallet::Wallet;

/// Auto-save manager for wallet
pub struct AutoSaveManager {
    wallet: Weak<RwLock<Wallet>>,
    interval_secs: u64,
}

impl AutoSaveManager {
    /// Create a new auto-save manager
    pub fn new(wallet: Weak<RwLock<Wallet>>, interval_secs: u64) -> Self {
        Self {
            wallet,
            interval_secs,
        }
    }

    /// Start the auto-save task
    pub async fn start(self) {
        let mut ticker = interval(Duration::from_secs(self.interval_secs));

        info!(
            "Starting wallet auto-save every {} seconds",
            self.interval_secs
        );

        loop {
            ticker.tick().await;

            // Try to get a strong reference to the wallet
            if let Some(wallet_arc) = self.wallet.upgrade() {
                debug!("Running wallet auto-save");

                // Get a read lock (save_wallet_state only reads data)
                let wallet = wallet_arc.read().await;

                if let Err(e) = wallet.save_wallet_state() {
                    error!("Failed to auto-save wallet: {}", e);
                } else {
                    debug!("Wallet auto-save completed successfully");
                }
            } else {
                // Wallet has been dropped, exit the task
                info!("Wallet dropped, stopping auto-save");
                break;
            }
        }
    }
}

/// Trait to add auto-save functionality to wallet
pub trait WalletAutoSave {
    /// Start auto-save with specified interval in seconds
    fn start_autosave(self: Arc<Self>, interval_secs: u64) -> tokio::task::JoinHandle<()>;
}

impl WalletAutoSave for RwLock<Wallet> {
    fn start_autosave(self: Arc<Self>, interval_secs: u64) -> tokio::task::JoinHandle<()> {
        let weak_ref = Arc::downgrade(&self);
        let manager = AutoSaveManager::new(weak_ref, interval_secs);

        tokio::spawn(async move {
            manager.start().await;
        })
    }
}

/// Default auto-save interval (5 minutes)
pub const DEFAULT_AUTOSAVE_INTERVAL: u64 = 300;

/// Fast auto-save interval for testing (10 seconds)
pub const FAST_AUTOSAVE_INTERVAL: u64 = 10;
