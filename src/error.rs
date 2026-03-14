//! Error types for cryptographic operations.

/// Errors from cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid public key length: expected 32, got {0}")]
    InvalidKeyLength(usize),

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Signature verification failed")]
    SignatureInvalid,

    #[error("Invalid signature encoding: {0}")]
    InvalidSignatureEncoding(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Integrity check failed: outer field '{0}' does not match signed payload")]
    IntegrityMismatch(String),

    #[error("Delegation chain broken: {0}")]
    DelegationChainBroken(String),

    #[error("Caveat violation: {0}")]
    CaveatViolation(String),

    #[error("Delegation revoked: {0}")]
    DelegationRevoked(String),
}
