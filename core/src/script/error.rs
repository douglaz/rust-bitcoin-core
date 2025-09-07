use thiserror::Error;

pub type ScriptResult<T> = Result<T, ScriptError>;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ScriptError {
    #[error("Script evaluation false")]
    EvalFalse,

    #[error("Script execution exceeded maximum operations")]
    OpCount,

    #[error("Stack size limit exceeded")]
    StackSize,

    #[error("Push size limit exceeded")]
    PushSize,

    #[error("Script size limit exceeded")]
    ScriptSize,

    #[error("Attempted to pop from empty stack")]
    InvalidStackOperation,

    #[error("Invalid altstack operation")]
    InvalidAltStackOperation,

    #[error("OP_RETURN was executed")]
    OpReturn,

    #[error("Invalid opcode")]
    BadOpcode,

    #[error("Disabled opcode")]
    DisabledOpcode,

    #[error("Negative locktime")]
    NegativeLocktime,

    #[error("Unsatisfied locktime")]
    UnsatisfiedLocktime,

    #[error("Signature verification failed")]
    CheckSigVerify,

    #[error("Multi-signature verification failed")]
    CheckMultiSigVerify,

    #[error("Public key count exceeded")]
    PubKeyCount,

    #[error("Signature count exceeded")]
    SigCount,

    #[error("Null dummy value in multisig")]
    NullDummy,

    #[error("Invalid signature hash type")]
    SigHashType,

    #[error("Invalid signature encoding")]
    SigDer,

    #[error("Signature high S value")]
    SigHighS,

    #[error("Public key not compressed")]
    PubKeyType,

    #[error("Stack must be clean after execution")]
    CleanStack,

    #[error("Minimal data encoding not used")]
    MinimalData,

    #[error("Invalid number encoding")]
    InvalidNumberEncoding,

    #[error("Number overflow")]
    NumberOverflow,

    #[error("Non-push operation in scriptSig")]
    SigPushOnly,

    #[error("Unbalanced conditional")]
    UnbalancedConditional,

    #[error("OP_EQUALVERIFY failed")]
    EqualVerify,

    #[error("OP_NUMEQUALVERIFY failed")]
    NumEqualVerify,

    #[error("OP_CHECKSIGVERIFY failed")]
    CheckSigVerifyFailed,

    #[error("OP_CHECKMULTISIGVERIFY failed")]
    CheckMultiSigVerifyFailed,

    #[error("Witness program version mismatch")]
    WitnessProgramMismatch,

    #[error("Witness program has wrong length")]
    WitnessProgramWrongLength,

    #[error("Witness program is empty")]
    WitnessProgramEmpty,

    #[error("Witness malleated")]
    WitnessMalleated,

    #[error("Witness has unexpected items")]
    WitnessUnexpected,

    #[error("Witness pubkey type mismatch")]
    WitnessPubkeyType,

    #[error("Discourage upgradeable witness program")]
    DiscourageUpgradeableWitnessProgram,

    #[error("Discourage upgradeable nops")]
    DiscourageUpgradeableNops,

    #[error("Discourage upgradeable taproot version")]
    DiscourageUpgradeableTaprootVersion,

    #[error("Taproot validation failed")]
    TaprootValidation,

    #[error("Invalid taproot key")]
    InvalidTaprootKey,

    #[error("Unknown error")]
    Unknown,
}
