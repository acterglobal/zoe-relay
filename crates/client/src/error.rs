use zoe_wire_protocol::MessageError;

use crate::SessionManagerError;

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("Generic error: {0}")]
    Generic(String),
    #[error("Build error: {0}")]
    BuildError(String),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Quinn connect error: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),
    #[error("Quinn connection error: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] zoe_wire_protocol::CryptoError),
    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("File storage error: {0}")]
    FileStorage(String),
    #[error("Encryption error: {0}")]
    Encryption(#[from] zoe_encrypted_storage::ConvergentEncryptionError),
    #[error("Blob store error: {0}")]
    BlobStore(#[from] zoe_blob_store::error::BlobStoreError),
    #[error("Challenge error: {0}")]
    Challenge(#[from] anyhow::Error),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Message Rpc error: {0}")]
    Message(#[from] MessageError),
    #[error("RPC error: {0}")]
    RpcError(#[from] tarpc::client::RpcError),
    #[error("Session manager error: {0}")]
    SessionManager(#[from] SessionManagerError),
    #[error("Storage error: {0}")]
    Storage(#[from] zoe_client_storage::StorageError),
}

pub type Result<T> = std::result::Result<T, ClientError>;
