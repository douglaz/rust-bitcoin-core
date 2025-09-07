//! Tests for Taproot activation logic (BIP341/342)

#[cfg(test)]
mod tests {
    use crate::consensus_rules::ConsensusRules;
    use bitcoin::Network;

    #[test]
    fn test_taproot_activation_mainnet() {
        let rules = ConsensusRules::new(Network::Bitcoin);
        
        // Before activation (block 709631)
        assert!(!rules.is_taproot_active(709631));
        assert!(!rules.is_taproot_active(700000));
        assert!(!rules.is_taproot_active(500000));
        
        // At activation (block 709632)
        assert!(rules.is_taproot_active(709632));
        
        // After activation
        assert!(rules.is_taproot_active(709633));
        assert!(rules.is_taproot_active(800000));
        assert!(rules.is_taproot_active(1000000));
    }

    #[test]
    fn test_taproot_activation_testnet() {
        let rules = ConsensusRules::new(Network::Testnet);
        
        // Before activation (block 2104440)
        assert!(!rules.is_taproot_active(2104440));
        assert!(!rules.is_taproot_active(2000000));
        assert!(!rules.is_taproot_active(1500000));
        
        // At activation (block 2104441)
        assert!(rules.is_taproot_active(2104441));
        
        // After activation
        assert!(rules.is_taproot_active(2104442));
        assert!(rules.is_taproot_active(2200000));
        assert!(rules.is_taproot_active(3000000));
    }

    #[test]
    fn test_taproot_activation_regtest() {
        let rules = ConsensusRules::new(Network::Regtest);
        
        // Taproot is always active on regtest from block 0
        assert!(rules.is_taproot_active(0));
        assert!(rules.is_taproot_active(1));
        assert!(rules.is_taproot_active(100));
        assert!(rules.is_taproot_active(1000));
    }

    #[test]
    fn test_segwit_activation_mainnet() {
        let rules = ConsensusRules::new(Network::Bitcoin);
        
        // Before activation (block 481823)
        assert!(!rules.is_segwit_active(481823));
        assert!(!rules.is_segwit_active(400000));
        assert!(!rules.is_segwit_active(300000));
        
        // At activation (block 481824)
        assert!(rules.is_segwit_active(481824));
        
        // After activation
        assert!(rules.is_segwit_active(481825));
        assert!(rules.is_segwit_active(500000));
        assert!(rules.is_segwit_active(700000));
    }

    #[test]
    fn test_segwit_activation_testnet() {
        let rules = ConsensusRules::new(Network::Testnet);
        
        // Before activation (block 834623)
        assert!(!rules.is_segwit_active(834623));
        assert!(!rules.is_segwit_active(800000));
        assert!(!rules.is_segwit_active(700000));
        
        // At activation (block 834624)
        assert!(rules.is_segwit_active(834624));
        
        // After activation
        assert!(rules.is_segwit_active(834625));
        assert!(rules.is_segwit_active(900000));
        assert!(rules.is_segwit_active(1000000));
    }

    #[test]
    fn test_script_flags_for_height() {
        let rules = ConsensusRules::new(Network::Bitcoin);
        
        // Test pre-SegWit height (block 400000)
        assert!(!rules.is_segwit_active(400000));
        assert!(!rules.is_taproot_active(400000));
        
        // Test post-SegWit, pre-Taproot height (block 600000)
        assert!(rules.is_segwit_active(600000));
        assert!(!rules.is_taproot_active(600000));
        
        // Test post-Taproot height (block 800000)
        assert!(rules.is_segwit_active(800000));
        assert!(rules.is_taproot_active(800000));
    }

    #[test]
    fn test_activation_boundaries() {
        let rules = ConsensusRules::new(Network::Bitcoin);
        
        // Test exact boundary conditions for Taproot
        assert!(!rules.is_taproot_active(709631), "Block before activation should not have Taproot");
        assert!(rules.is_taproot_active(709632), "First activation block should have Taproot");
        
        // Test exact boundary conditions for SegWit
        assert!(!rules.is_segwit_active(481823), "Block before activation should not have SegWit");
        assert!(rules.is_segwit_active(481824), "First activation block should have SegWit");
    }

    #[test]
    fn test_regtest_immediate_activation() {
        let rules = ConsensusRules::new(Network::Regtest);
        
        // On regtest, both SegWit and Taproot should be active from genesis
        assert!(rules.is_segwit_active(0));
        assert!(rules.is_taproot_active(0));
        assert!(rules.is_segwit_active(1));
        assert!(rules.is_taproot_active(1));
        assert!(rules.is_segwit_active(100));
        assert!(rules.is_taproot_active(100));
    }

    #[test]
    fn test_consensus_feature_progression() {
        // Test that consensus features are properly activated as height increases
        let rules = ConsensusRules::new(Network::Bitcoin);
        
        // Pre-SegWit
        assert!(!rules.is_segwit_active(400000));
        assert!(!rules.is_taproot_active(400000));
        
        // Post-SegWit, pre-Taproot
        assert!(rules.is_segwit_active(600000));
        assert!(!rules.is_taproot_active(600000));
        
        // Post-Taproot
        assert!(rules.is_segwit_active(800000));
        assert!(rules.is_taproot_active(800000));
    }
}