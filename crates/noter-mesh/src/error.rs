use thiserror::Error;

#[derive(Debug, Error)]
pub enum MeshError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] noter_crypto::CryptoError),
    #[error("handshake failed: {0}")]
    Handshake(&'static str),
    #[error("bad frame: {0}")]
    BadFrame(&'static str),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("peer closed the session")]
    Closed,
}
