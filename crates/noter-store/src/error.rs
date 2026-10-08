use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] noter_crypto::CryptoError),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("note not found: {0}")]
    NotFound(String),
    #[error("attachment not found: {0}")]
    AttachmentNotFound(String),
    #[error("wrong key or corrupt database")]
    BadKey,
}
