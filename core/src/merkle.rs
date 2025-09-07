use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{Transaction, TxMerkleNode, Txid};
use std::io::Write;

/// Calculate the merkle root for a set of transactions
pub fn calculate_merkle_root(transactions: &[Transaction]) -> TxMerkleNode {
    if transactions.is_empty() {
        return TxMerkleNode::from_byte_array([0u8; 32]);
    }

    let hashes: Vec<_> = transactions.iter().map(|tx| tx.compute_txid()).collect();

    calculate_merkle_root_from_txids(&hashes)
}

/// Calculate the merkle root from transaction IDs
pub fn calculate_merkle_root_from_txids(txids: &[Txid]) -> TxMerkleNode {
    if txids.is_empty() {
        return TxMerkleNode::from_byte_array([0u8; 32]);
    }

    let mut hashes: Vec<sha256d::Hash> = txids.iter().map(|txid| txid.to_raw_hash()).collect();

    if hashes.len() == 1 {
        return TxMerkleNode::from_raw_hash(hashes[0]);
    }

    // Build merkle tree layer by layer
    while hashes.len() > 1 {
        // If odd number of hashes, duplicate the last one
        if hashes.len() % 2 != 0 {
            hashes.push(*hashes.last().unwrap());
        }

        let mut new_hashes = Vec::new();
        for chunk in hashes.chunks(2) {
            let mut engine = sha256d::Hash::engine();
            engine.write_all(chunk[0].as_ref()).unwrap();
            engine.write_all(chunk[1].as_ref()).unwrap();
            new_hashes.push(sha256d::Hash::from_engine(engine));
        }

        hashes = new_hashes;
    }

    TxMerkleNode::from_raw_hash(hashes[0])
}

/// Build a complete merkle tree and return all intermediate hashes
pub struct MerkleTree {
    /// All levels of the tree, from leaves to root
    levels: Vec<Vec<sha256d::Hash>>,
}

impl MerkleTree {
    /// Build a merkle tree from transactions
    pub fn from_transactions(transactions: &[Transaction]) -> Self {
        let txids: Vec<_> = transactions.iter().map(|tx| tx.compute_txid()).collect();
        Self::from_txids(&txids)
    }

    /// Build a merkle tree from transaction IDs
    pub fn from_txids(txids: &[Txid]) -> Self {
        if txids.is_empty() {
            return Self {
                levels: vec![vec![sha256d::Hash::all_zeros()]],
            };
        }

        let mut levels = Vec::new();
        let mut current_level: Vec<sha256d::Hash> =
            txids.iter().map(|txid| txid.to_raw_hash()).collect();

        levels.push(current_level.clone());

        while current_level.len() > 1 {
            // If odd number of hashes, duplicate the last one
            if current_level.len() % 2 != 0 {
                current_level.push(*current_level.last().unwrap());
            }

            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let mut engine = sha256d::Hash::engine();
                engine.write_all(chunk[0].as_ref()).unwrap();
                engine.write_all(chunk[1].as_ref()).unwrap();
                next_level.push(sha256d::Hash::from_engine(engine));
            }

            levels.push(next_level.clone());
            current_level = next_level;
        }

        Self { levels }
    }

    /// Get the merkle root
    pub fn root(&self) -> TxMerkleNode {
        TxMerkleNode::from_raw_hash(
            *self
                .levels
                .last()
                .and_then(|level| level.first())
                .unwrap_or(&sha256d::Hash::all_zeros()),
        )
    }

    /// Get merkle branch for a transaction at given index
    pub fn get_merkle_branch(&self, index: usize) -> Vec<sha256d::Hash> {
        let mut branch = Vec::new();
        let mut idx = index;

        for level in &self.levels[..self.levels.len() - 1] {
            if idx >= level.len() {
                break;
            }

            // Get sibling hash
            let sibling_idx = if idx % 2 == 0 {
                // Even index: sibling is next (or duplicate if last)
                if idx + 1 < level.len() {
                    idx + 1
                } else {
                    idx
                }
            } else {
                // Odd index: sibling is previous
                idx - 1
            };

            branch.push(level[sibling_idx]);
            idx /= 2;
        }

        branch
    }

    /// Verify a merkle branch
    pub fn verify_branch(
        txid: &Txid,
        branch: &[sha256d::Hash],
        index: usize,
        root: &TxMerkleNode,
    ) -> bool {
        let mut hash = txid.to_raw_hash();
        let mut idx = index;

        for sibling in branch {
            let mut engine = sha256d::Hash::engine();

            if idx % 2 == 0 {
                // We are on the left
                engine.write_all(hash.as_ref()).unwrap();
                engine.write_all(sibling.as_ref()).unwrap();
            } else {
                // We are on the right
                engine.write_all(sibling.as_ref()).unwrap();
                engine.write_all(hash.as_ref()).unwrap();
            }

            hash = sha256d::Hash::from_engine(engine);
            idx /= 2;
        }

        TxMerkleNode::from_raw_hash(hash) == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    fn create_test_transaction(nonce: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(nonce),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn test_single_transaction_merkle_root() {
        let tx = create_test_transaction(1);
        let root = calculate_merkle_root(&[tx.clone()]);
        assert_eq!(
            root,
            TxMerkleNode::from_raw_hash(tx.compute_txid().to_raw_hash())
        );
    }

    #[test]
    fn test_two_transaction_merkle_root() {
        let tx1 = create_test_transaction(1);
        let tx2 = create_test_transaction(2);
        let txs = vec![tx1.clone(), tx2.clone()];

        let root = calculate_merkle_root(&txs);

        // Calculate expected root manually
        let mut engine = sha256d::Hash::engine();
        engine.write_all(tx1.compute_txid().as_ref()).unwrap();
        engine.write_all(tx2.compute_txid().as_ref()).unwrap();
        let expected = sha256d::Hash::from_engine(engine);

        assert_eq!(root, TxMerkleNode::from_raw_hash(expected));
    }

    #[test]
    fn test_odd_number_transaction_merkle_root() {
        let tx1 = create_test_transaction(1);
        let tx2 = create_test_transaction(2);
        let tx3 = create_test_transaction(3);
        let txs = vec![tx1, tx2, tx3.clone()];

        let root = calculate_merkle_root(&txs);

        // With 3 transactions, the last one should be duplicated
        // So we should have pairs: (tx1, tx2) and (tx3, tx3)
        assert_ne!(root, TxMerkleNode::from_byte_array([0u8; 32]));
    }

    #[test]
    fn test_merkle_tree_structure() {
        let txs: Vec<_> = (0..4).map(create_test_transaction).collect();
        let tree = MerkleTree::from_transactions(&txs);

        // Should have 3 levels: 4 leaves -> 2 nodes -> 1 root
        assert_eq!(tree.levels.len(), 3);
        assert_eq!(tree.levels[0].len(), 4); // Leaf level
        assert_eq!(tree.levels[1].len(), 2); // Intermediate level
        assert_eq!(tree.levels[2].len(), 1); // Root level
    }

    #[test]
    fn test_merkle_branch_verification() {
        let txs: Vec<_> = (0..4).map(create_test_transaction).collect();
        let tree = MerkleTree::from_transactions(&txs);

        // Get branch for second transaction (index 1)
        let branch = tree.get_merkle_branch(1);

        // Verify the branch
        let verified = MerkleTree::verify_branch(&txs[1].compute_txid(), &branch, 1, &tree.root());

        assert!(verified);
    }

    #[test]
    fn test_empty_merkle_root() {
        let root = calculate_merkle_root(&[]);
        assert_eq!(root, TxMerkleNode::from_byte_array([0u8; 32]));
    }
}
