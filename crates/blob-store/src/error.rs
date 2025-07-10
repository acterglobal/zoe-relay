use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

/// Error type for blob store operations
#[derive(Error, Debug)]
pub enum BlobStoreError {
    #[error("Blob not found: {0}")]
    NotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Hash parsing error: {0}")]
    HashParse(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Request error: {0}")]
    Request(String),
}

impl From<anyhow::Error> for BlobStoreError {
    fn from(err: anyhow::Error) -> Self {
        BlobStoreError::Internal(err.to_string())
    }
}

impl From<irpc::Error> for BlobStoreError {
    fn from(err: irpc::Error) -> Self {
        BlobStoreError::Request(err.to_string())
    }
}

impl From<iroh_blobs::api::RequestError> for BlobStoreError {
    fn from(err: iroh_blobs::api::RequestError) -> Self {
        BlobStoreError::Request(err.to_string())
    }
}

impl IntoResponse for BlobStoreError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            BlobStoreError::NotFound(hash) => {
                (StatusCode::NOT_FOUND, format!("Blob not found: {}", hash))
            }
            BlobStoreError::InvalidInput(msg) => {
                (StatusCode::BAD_REQUEST, format!("Invalid input: {}", msg))
            }
            BlobStoreError::Storage(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", err),
            ),
            BlobStoreError::Io(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("IO error: {}", err),
            ),
            BlobStoreError::Serialization(err) => (
                StatusCode::BAD_REQUEST,
                format!("Serialization error: {}", err),
            ),
            BlobStoreError::HashParse(err) => (
                StatusCode::BAD_REQUEST,
                format!("Hash parsing error: {}", err),
            ),
            BlobStoreError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal error: {}", msg),
            ),
            BlobStoreError::Request(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Request error: {}", msg),
            ),
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}
