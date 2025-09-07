use bitcoin::Amount;
use tracing::{debug, info};

use crate::balance::Utxo;
use crate::error::{WalletError, WalletResult};
use crate::transaction::FeeRate;

/// Result of coin selection
#[derive(Debug, Clone)]
pub struct CoinSelectionResult {
    pub selected_utxos: Vec<Utxo>,
    pub total_input: Amount,
    pub change_amount: Amount,
    pub fee: Amount,
}

/// Coin selection algorithm type
#[derive(Debug, Clone, Copy)]
pub enum CoinSelectionAlgorithm {
    /// Largest first (simple greedy)
    LargestFirst,
    /// Smallest first (minimize UTXO set)
    SmallestFirst,
    /// Branch and Bound (optimal)
    BranchAndBound,
    /// Single Random Draw
    SingleRandomDraw,
    /// Knapsack solver
    Knapsack,
}

/// Coin selector
pub struct CoinSelector {
    available_utxos: Vec<Utxo>,
    fee_rate: FeeRate,
    min_change: Amount,
    algorithm: CoinSelectionAlgorithm,
}

impl CoinSelector {
    /// Create a new coin selector
    pub fn new(available_utxos: Vec<Utxo>, fee_rate: FeeRate) -> Self {
        Self {
            available_utxos,
            fee_rate,
            min_change: Amount::from_sat(546), // Dust threshold
            algorithm: CoinSelectionAlgorithm::BranchAndBound,
        }
    }

    /// Set the algorithm to use
    pub fn with_algorithm(mut self, algorithm: CoinSelectionAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set minimum change amount
    pub fn with_min_change(mut self, min_change: Amount) -> Self {
        self.min_change = min_change;
        self
    }

    /// Select coins for the target amount
    pub fn select_coins(&self, target_amount: Amount) -> WalletResult<CoinSelectionResult> {
        debug!(
            "Selecting coins for target amount: {} sats",
            target_amount.to_sat()
        );
        debug!("Using algorithm: {:?}", self.algorithm);
        debug!("Available UTXOs: {}", self.available_utxos.len());

        if self.available_utxos.is_empty() {
            return Err(WalletError::InsufficientFunds {
                required: target_amount.to_sat(),
                available: 0,
            });
        }

        let result = match self.algorithm {
            CoinSelectionAlgorithm::LargestFirst => self.select_largest_first(target_amount),
            CoinSelectionAlgorithm::SmallestFirst => self.select_smallest_first(target_amount),
            CoinSelectionAlgorithm::BranchAndBound => self.select_branch_and_bound(target_amount),
            CoinSelectionAlgorithm::SingleRandomDraw => {
                self.select_single_random_draw(target_amount)
            }
            CoinSelectionAlgorithm::Knapsack => self.select_knapsack(target_amount),
        }?;

        info!(
            "Selected {} UTXOs, total input: {} sats, change: {} sats, fee: {} sats",
            result.selected_utxos.len(),
            result.total_input.to_sat(),
            result.change_amount.to_sat(),
            result.fee.to_sat()
        );

        Ok(result)
    }

    /// Largest first selection (simple greedy)
    fn select_largest_first(&self, target_amount: Amount) -> WalletResult<CoinSelectionResult> {
        let mut selected = Vec::new();
        let mut total_input = Amount::ZERO;

        // Sort by value descending
        let mut utxos = self.available_utxos.clone();
        utxos.sort_by_key(|u| std::cmp::Reverse(u.output.value));

        for utxo in utxos {
            selected.push(utxo.clone());
            total_input += utxo.output.value;

            let estimated_fee = self.estimate_fee(&selected);
            let required = target_amount + estimated_fee;

            if total_input >= required {
                let change = total_input - target_amount - estimated_fee;
                return Ok(CoinSelectionResult {
                    selected_utxos: selected,
                    total_input,
                    change_amount: change,
                    fee: estimated_fee,
                });
            }
        }

        Err(WalletError::InsufficientFunds {
            required: target_amount.to_sat(),
            available: total_input.to_sat(),
        })
    }

    /// Smallest first selection (minimize UTXO set)
    fn select_smallest_first(&self, target_amount: Amount) -> WalletResult<CoinSelectionResult> {
        let mut selected = Vec::new();
        let mut total_input = Amount::ZERO;

        // Sort by value ascending
        let mut utxos = self.available_utxos.clone();
        utxos.sort_by_key(|u| u.output.value);

        for utxo in utxos {
            selected.push(utxo.clone());
            total_input += utxo.output.value;

            let estimated_fee = self.estimate_fee(&selected);
            let required = target_amount + estimated_fee;

            if total_input >= required {
                let change = total_input - target_amount - estimated_fee;
                return Ok(CoinSelectionResult {
                    selected_utxos: selected,
                    total_input,
                    change_amount: change,
                    fee: estimated_fee,
                });
            }
        }

        Err(WalletError::InsufficientFunds {
            required: target_amount.to_sat(),
            available: total_input.to_sat(),
        })
    }

    /// Branch and Bound selection (BIP 125)
    /// Finds the selection with minimum waste
    fn select_branch_and_bound(&self, target_amount: Amount) -> WalletResult<CoinSelectionResult> {
        const MAX_ITERATIONS: usize = 100000;

        // Add fee to target
        let initial_fee = self.estimate_fee(&[]);
        let target_with_fee = target_amount + initial_fee;

        // Sort UTXOs by effective value (value - cost to spend)
        let mut effective_utxos: Vec<(Utxo, Amount)> = Vec::new();
        for utxo in &self.available_utxos {
            let cost_to_spend = self.estimate_input_fee();
            if utxo.output.value > cost_to_spend {
                let effective_value = utxo.output.value - cost_to_spend;
                effective_utxos.push((utxo.clone(), effective_value));
            }
        }

        effective_utxos.sort_by_key(|(_, ev)| std::cmp::Reverse(*ev));

        // Branch and bound search
        let mut best_selection: Option<Vec<Utxo>> = None;
        let mut best_waste = Amount::MAX;

        let mut current_selection = Vec::new();
        let mut current_value = Amount::ZERO;
        let mut iterations = 0;

        self.branch_and_bound_recurse(
            &effective_utxos,
            target_with_fee,
            &mut current_selection,
            &mut current_value,
            0,
            &mut best_selection,
            &mut best_waste,
            &mut iterations,
            MAX_ITERATIONS,
        );

        if let Some(selected) = best_selection {
            let total_input: Amount = selected.iter().map(|u| u.output.value).sum();
            let fee = self.estimate_fee(&selected);
            let change = total_input - target_amount - fee;

            return Ok(CoinSelectionResult {
                selected_utxos: selected,
                total_input,
                change_amount: change,
                fee,
            });
        }

        // Fall back to largest first if branch and bound fails
        self.select_largest_first(target_amount)
    }

    /// Recursive helper for branch and bound
    fn branch_and_bound_recurse(
        &self,
        utxos: &[(Utxo, Amount)],
        target: Amount,
        current_selection: &mut Vec<Utxo>,
        current_value: &mut Amount,
        depth: usize,
        best_selection: &mut Option<Vec<Utxo>>,
        best_waste: &mut Amount,
        iterations: &mut usize,
        max_iterations: usize,
    ) {
        *iterations += 1;
        if *iterations > max_iterations {
            return;
        }

        // Base case: we've considered all UTXOs
        if depth >= utxos.len() {
            if *current_value >= target {
                let waste = *current_value - target;
                if waste < *best_waste {
                    *best_waste = waste;
                    *best_selection = Some(current_selection.clone());
                }
            }
            return;
        }

        // Prune: if current waste is already worse than best, skip
        if *current_value > target {
            let waste = *current_value - target;
            if waste >= *best_waste {
                return;
            }
        }

        // Try including current UTXO
        let (utxo, effective_value) = &utxos[depth];
        current_selection.push(utxo.clone());
        *current_value += *effective_value;

        self.branch_and_bound_recurse(
            utxos,
            target,
            current_selection,
            current_value,
            depth + 1,
            best_selection,
            best_waste,
            iterations,
            max_iterations,
        );

        // Backtrack
        current_selection.pop();
        *current_value -= *effective_value;

        // Try not including current UTXO (only if we can still reach target)
        let remaining_sum: Amount = utxos[depth + 1..].iter().map(|(_, ev)| *ev).sum();

        if *current_value + remaining_sum >= target {
            self.branch_and_bound_recurse(
                utxos,
                target,
                current_selection,
                current_value,
                depth + 1,
                best_selection,
                best_waste,
                iterations,
                max_iterations,
            );
        }
    }

    /// Single Random Draw selection
    /// Randomly select UTXOs until target is met
    fn select_single_random_draw(
        &self,
        target_amount: Amount,
    ) -> WalletResult<CoinSelectionResult> {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        let mut rng = thread_rng();
        let mut utxos = self.available_utxos.clone();
        utxos.shuffle(&mut rng);

        let mut selected = Vec::new();
        let mut total_input = Amount::ZERO;

        for utxo in utxos {
            selected.push(utxo.clone());
            total_input += utxo.output.value;

            let estimated_fee = self.estimate_fee(&selected);
            let required = target_amount + estimated_fee;

            if total_input >= required {
                let change = total_input - target_amount - estimated_fee;
                return Ok(CoinSelectionResult {
                    selected_utxos: selected,
                    total_input,
                    change_amount: change,
                    fee: estimated_fee,
                });
            }
        }

        Err(WalletError::InsufficientFunds {
            required: target_amount.to_sat(),
            available: total_input.to_sat(),
        })
    }

    /// Knapsack solver selection
    /// Approximation algorithm for the subset sum problem
    fn select_knapsack(&self, target_amount: Amount) -> WalletResult<CoinSelectionResult> {
        const MIN_CHANGE: u64 = 1000; // Minimum change to avoid dust

        // Add some buffer to target for fees
        let estimated_fee = self.estimate_fee_for_inputs(self.available_utxos.len());
        let target_with_buffer = target_amount + estimated_fee + Amount::from_sat(MIN_CHANGE);

        let mut applicable_utxos = Vec::new();
        let mut total_lower = Amount::ZERO;

        // Filter UTXOs and calculate totals
        for utxo in &self.available_utxos {
            if utxo.output.value <= target_with_buffer {
                applicable_utxos.push(utxo.clone());
                total_lower += utxo.output.value;
            }
        }

        // If we have enough with just smaller UTXOs, use them
        if total_lower >= target_with_buffer {
            return self.knapsack_solver(&applicable_utxos, target_with_buffer);
        }

        // Otherwise, add one larger UTXO
        for utxo in &self.available_utxos {
            if utxo.output.value > target_with_buffer {
                let selected = vec![utxo.clone()];
                let fee = self.estimate_fee(&selected);
                let change = utxo.output.value - target_amount - fee;

                return Ok(CoinSelectionResult {
                    selected_utxos: selected,
                    total_input: utxo.output.value,
                    change_amount: change,
                    fee,
                });
            }
        }

        // Fall back to using all applicable UTXOs
        self.knapsack_solver(&applicable_utxos, target_amount)
    }

    /// Knapsack solver implementation
    fn knapsack_solver(&self, utxos: &[Utxo], target: Amount) -> WalletResult<CoinSelectionResult> {
        const TOTAL_TRIES: usize = 1000;

        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();

        let mut best_selection = Vec::new();
        let mut best_value = Amount::ZERO;

        for _ in 0..TOTAL_TRIES {
            let mut included = vec![false; utxos.len()];
            let mut total = Amount::ZERO;

            // Randomly include/exclude each UTXO
            for (i, utxo) in utxos.iter().enumerate() {
                if rng.gen_bool(0.5) {
                    included[i] = true;
                    total += utxo.output.value;
                }
            }

            // Check if this selection is better
            if total >= target && (best_value == Amount::ZERO || total < best_value) {
                best_value = total;
                best_selection = included.clone();
            }
        }

        if best_value > Amount::ZERO {
            let selected: Vec<Utxo> = utxos
                .iter()
                .zip(best_selection.iter())
                .filter_map(
                    |(utxo, &included)| {
                        if included {
                            Some(utxo.clone())
                        } else {
                            None
                        }
                    },
                )
                .collect();

            let fee = self.estimate_fee(&selected);
            let change = best_value - target - fee;

            Ok(CoinSelectionResult {
                selected_utxos: selected,
                total_input: best_value,
                change_amount: change,
                fee,
            })
        } else {
            // If random selection fails, fall back to largest first
            self.select_largest_first(target)
        }
    }

    /// Estimate fee for selected UTXOs
    fn estimate_fee(&self, selected: &[Utxo]) -> Amount {
        // Base transaction size (version, locktime, counts)
        let base_size = 10;

        // Input size (P2WPKH assumed)
        let input_size = selected.len() * 68; // 68 bytes per P2WPKH input

        // Output size (2 outputs: payment + change)
        let output_size = 2 * 31; // 31 bytes per P2WPKH output

        // Witness size
        let witness_size = selected.len() * 107; // ~107 bytes per P2WPKH witness

        // Calculate weight
        let tx_size = base_size + input_size + output_size;
        let weight = tx_size * 4 + witness_size;
        let vsize = weight.div_ceil(4); // Round up

        self.fee_rate.calculate_fee(vsize)
    }

    /// Estimate fee for a single input
    fn estimate_input_fee(&self) -> Amount {
        // P2WPKH input: ~68 bytes base + ~107 witness bytes
        // Weight = 68 * 4 + 107 = 379
        // vSize = (379 + 3) / 4 = 95 vBytes
        self.fee_rate.calculate_fee(95)
    }

    /// Estimate fee for N inputs
    fn estimate_fee_for_inputs(&self, num_inputs: usize) -> Amount {
        let base_size = 10;
        let input_size = num_inputs * 68;
        let output_size = 2 * 31;
        let witness_size = num_inputs * 107;

        let tx_size = base_size + input_size + output_size;
        let weight = tx_size * 4 + witness_size;
        let vsize = weight.div_ceil(4);

        self.fee_rate.calculate_fee(vsize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{OutPoint, TxOut};

    fn create_test_utxo(value_sats: u64) -> Utxo {
        use bitcoin::hashes::Hash;

        Utxo {
            outpoint: OutPoint {
                txid: bitcoin::Txid::from_raw_hash(
                    bitcoin::hashes::sha256d::Hash::from_slice(&[0u8; 32]).unwrap(),
                ),
                vout: 0,
            },
            output: TxOut {
                value: Amount::from_sat(value_sats),
                script_pubkey: bitcoin::ScriptBuf::new(),
            },
            height: Some(100),
            address: "bc1qtest".to_string(),
            confirmations: 10,
        }
    }

    #[test]
    fn test_largest_first_selection() {
        let utxos = vec![
            create_test_utxo(10000),
            create_test_utxo(20000),
            create_test_utxo(30000),
            create_test_utxo(5000),
        ];

        let selector = CoinSelector::new(utxos, FeeRate::from_sat_per_vb(10))
            .with_algorithm(CoinSelectionAlgorithm::LargestFirst);

        let result = selector.select_coins(Amount::from_sat(25000)).unwrap();

        assert_eq!(result.selected_utxos.len(), 1);
        assert_eq!(
            result.selected_utxos[0].output.value,
            Amount::from_sat(30000)
        );
    }

    #[test]
    fn test_smallest_first_selection() {
        let utxos = vec![
            create_test_utxo(10000),
            create_test_utxo(20000),
            create_test_utxo(30000),
            create_test_utxo(5000),
        ];

        let selector = CoinSelector::new(utxos, FeeRate::from_sat_per_vb(10))
            .with_algorithm(CoinSelectionAlgorithm::SmallestFirst);

        let result = selector.select_coins(Amount::from_sat(25000)).unwrap();

        // Should select 5000, 10000, 20000 = 35000
        assert_eq!(result.selected_utxos.len(), 3);
        assert_eq!(result.total_input, Amount::from_sat(35000));
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos = vec![create_test_utxo(10000), create_test_utxo(5000)];

        let selector = CoinSelector::new(utxos, FeeRate::from_sat_per_vb(10));

        let result = selector.select_coins(Amount::from_sat(50000));
        assert!(result.is_err());
    }
}
