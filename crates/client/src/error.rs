#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("Generic error: {0}")]
    Generic(String),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Quinn connect error: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),
    #[error("Quinn connection error: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
}

pub type Result<T> = std::result::Result<T, ClientError>;
