use bitflags::bitflags;

bitflags! {
    /// Script verification flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ScriptFlags: u32 {
        /// No flags
        const NONE = 0;

        /// Evaluate P2SH subscripts
        const P2SH = 1 << 0;

        /// Enforce strict DER signatures
        const STRICTENC = 1 << 1;

        /// Enforce low S values in signatures
        const LOW_S = 1 << 2;

        /// Enforce strict signature hash type
        const SIGHASH_FORKID = 1 << 3;

        /// Enforce minimal push data
        const MINIMALDATA = 1 << 4;

        /// Discourage use of NOPs reserved for upgrades
        const DISCOURAGE_UPGRADEABLE_NOPS = 1 << 5;

        /// Require that only a single stack element remains after evaluation
        const CLEANSTACK = 1 << 6;

        /// Verify dummy stack item consumed by CHECKMULTISIG is null
        const NULLDUMMY = 1 << 7;

        /// Using a non-push operator in scriptSig causes failure
        const SIGPUSHONLY = 1 << 8;

        /// Require minimal encodings for all push operations
        const MINIMALIF = 1 << 9;

        /// Signature(s) must not use the SIGHASH_SINGLE bug
        const NULLFAIL = 1 << 10;

        /// Enable CHECKLOCKTIMEVERIFY (BIP65)
        const CHECKLOCKTIMEVERIFY = 1 << 11;

        /// Enable CHECKSEQUENCEVERIFY (BIP112)
        const CHECKSEQUENCEVERIFY = 1 << 12;

        /// Enable witness (BIP141)
        const WITNESS = 1 << 13;

        /// Discourage use of witness versions reserved for upgrades
        const DISCOURAGE_UPGRADEABLE_WITNESS_PROGRAM = 1 << 14;

        /// Require compressed keys in segwit
        const WITNESS_PUBKEYTYPE = 1 << 15;

        /// Enable taproot (BIP341)
        const TAPROOT = 1 << 16;

        /// Discourage unknown taproot versions
        const DISCOURAGE_UPGRADEABLE_TAPROOT_VERSION = 1 << 17;

        /// Discourage OP_SUCCESS opcodes
        const DISCOURAGE_OP_SUCCESS = 1 << 18;

        /// Discourage unknown public key types
        const DISCOURAGE_UPGRADEABLE_PUBKEYTYPE = 1 << 19;

        /// Standard script verification flags
        const STANDARD = Self::P2SH.bits() |
                         Self::STRICTENC.bits() |
                         Self::LOW_S.bits() |
                         Self::MINIMALDATA.bits() |
                         Self::DISCOURAGE_UPGRADEABLE_NOPS.bits() |
                         Self::CLEANSTACK.bits() |
                         Self::NULLDUMMY.bits() |
                         Self::CHECKLOCKTIMEVERIFY.bits() |
                         Self::CHECKSEQUENCEVERIFY.bits() |
                         Self::WITNESS.bits() |
                         Self::DISCOURAGE_UPGRADEABLE_WITNESS_PROGRAM.bits() |
                         Self::WITNESS_PUBKEYTYPE.bits() |
                         Self::TAPROOT.bits();

        /// Mandatory script verification flags that all blocks must comply with
        const MANDATORY = Self::P2SH.bits() |
                         Self::STRICTENC.bits() |
                         Self::CHECKLOCKTIMEVERIFY.bits() |
                         Self::CHECKSEQUENCEVERIFY.bits() |
                         Self::WITNESS.bits() |
                         Self::TAPROOT.bits();
    }
}

impl Default for ScriptFlags {
    fn default() -> Self {
        ScriptFlags::STANDARD
    }
}

impl ScriptFlags {
    /// Check if P2SH validation is enabled
    pub fn verify_p2sh(&self) -> bool {
        self.contains(ScriptFlags::P2SH)
    }

    /// Check if witness validation is enabled
    pub fn verify_witness(&self) -> bool {
        self.contains(ScriptFlags::WITNESS)
    }

    /// Check if taproot validation is enabled
    pub fn verify_taproot(&self) -> bool {
        self.contains(ScriptFlags::TAPROOT)
    }

    /// Check if strict encoding is required
    pub fn require_strict_encoding(&self) -> bool {
        self.contains(ScriptFlags::STRICTENC)
    }

    /// Check if minimal data encoding is required
    pub fn require_minimal(&self) -> bool {
        self.contains(ScriptFlags::MINIMALDATA)
    }

    /// Get flags for a specific block height
    pub fn for_block_height(height: u32, is_testnet: bool) -> Self {
        let mut flags = ScriptFlags::NONE;

        // BIP16 (P2SH) activated at height 173805 on mainnet
        if (!is_testnet && height >= 173805) || is_testnet {
            flags |= ScriptFlags::P2SH;
        }

        // BIP65 (CHECKLOCKTIMEVERIFY) activated at height 388381 on mainnet
        if (!is_testnet && height >= 388381) || is_testnet {
            flags |= ScriptFlags::CHECKLOCKTIMEVERIFY;
        }

        // BIP66 (Strict DER) activated at height 363724 on mainnet
        if (!is_testnet && height >= 363724) || is_testnet {
            flags |= ScriptFlags::STRICTENC;
        }

        // BIP112 (CHECKSEQUENCEVERIFY) activated at height 419328 on mainnet
        if (!is_testnet && height >= 419328) || is_testnet {
            flags |= ScriptFlags::CHECKSEQUENCEVERIFY;
        }

        // SegWit activated at height 481824 on mainnet
        if (!is_testnet && height >= 481824) || is_testnet {
            flags |= ScriptFlags::WITNESS;
        }

        // Taproot activated at height 709632 on mainnet
        if (!is_testnet && height >= 709632) || is_testnet {
            flags |= ScriptFlags::TAPROOT;
        }

        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_flags() {
        let flags = ScriptFlags::STANDARD;
        assert!(flags.verify_p2sh());
        assert!(flags.verify_witness());
        assert!(flags.verify_taproot());
        assert!(flags.require_strict_encoding());

        let mandatory = ScriptFlags::MANDATORY;
        assert!(mandatory.verify_p2sh());
        assert!(mandatory.verify_witness());
        assert!(mandatory.verify_taproot());
    }

    #[test]
    fn test_height_activation() {
        // Test mainnet activation heights
        let pre_p2sh = ScriptFlags::for_block_height(173804, false);
        assert!(!pre_p2sh.verify_p2sh());

        let post_p2sh = ScriptFlags::for_block_height(173805, false);
        assert!(post_p2sh.verify_p2sh());

        let post_segwit = ScriptFlags::for_block_height(481824, false);
        assert!(post_segwit.verify_witness());

        let post_taproot = ScriptFlags::for_block_height(709632, false);
        assert!(post_taproot.verify_taproot());

        // Test testnet (all features enabled)
        let testnet = ScriptFlags::for_block_height(0, true);
        assert!(testnet.verify_p2sh());
        assert!(testnet.verify_witness());
        assert!(testnet.verify_taproot());
    }
}
