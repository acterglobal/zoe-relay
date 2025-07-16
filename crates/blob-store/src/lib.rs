use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use iroh_blobs::{Hash, store::fs::FsStore};
use serde::Serialize;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

pub mod error;
pub mod server;
pub mod service;

pub use error::*;
pub use server::*;
pub use service::*;

/// Configuration for the blob store
#[derive(Debug, Clone)]
pub struct BlobStoreConfig {
    /// Base directory for storing blobs
    pub data_dir: PathBuf,
    /// HTTP server port
    pub port: u16,
    /// Host address to bind to
    pub host: String,
}

impl Default for BlobStoreConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./blob-store-data"),
            port: 8080,
            host: "127.0.0.1".to_string(),
        }
    }
}

/// Main blob store service
pub struct BlobStoreService {
    store: Arc<FsStore>,
    config: BlobStoreConfig,
}

impl BlobStoreService {
    /// Create a new blob store service
    pub async fn new(config: BlobStoreConfig) -> Result<Self, BlobStoreError> {
        // Ensure data directory exists
        tokio::fs::create_dir_all(&config.data_dir)
            .await
            .context("Failed to create data directory")?;

        // Create the iroh blob store
        let store = FsStore::load(&config.data_dir)
            .await
            .context("Failed to create blob store")?;

        Ok(Self {
            store: Arc::new(store),
            config,
        })
    }

    /// Get a reference to the underlying store
    pub fn store(&self) -> &FsStore {
        &self.store
    }

    /// Get the configuration
    pub fn config(&self) -> &BlobStoreConfig {
        &self.config
    }
}

/// Application state shared across HTTP handlers
#[derive(Clone)]
pub struct AppState {
    service: Arc<BlobStoreService>,
}

/// Response for blob upload
#[derive(Debug, Serialize)]
pub struct UploadResponse {
    hash: String,
    size: u64,
}

/// Response for blob info
#[derive(Debug, Serialize)]
pub struct BlobInfo {
    hash: String,
    size: u64,
    exists: bool,
}

/// Upload a blob via HTTP POST
async fn upload_blob(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> Result<Json<UploadResponse>, BlobStoreError> {
    if body.is_empty() {
        return Err(BlobStoreError::InvalidInput("Empty blob data".to_string()));
    }

    // Store the blob using add_bytes
    let progress = state.service.store().add_bytes(body.clone());
    let result = progress.await?;
    let hash = result.hash;

    info!("Uploaded blob: {} ({} bytes)", hash, body.len());

    Ok(Json(UploadResponse {
        hash: hash.to_string(),
        size: body.len() as u64,
    }))
}

/// Get blob info by hash
async fn get_blob_info(
    State(state): State<AppState>,
    Path(hash_str): Path<String>,
) -> Result<Json<BlobInfo>, BlobStoreError> {
    let hash = hash_str.parse::<Hash>().context("Invalid hash format")?;

    let exists = state.service.store().has(hash).await?;
    let size = if exists {
        // Get the blob size by trying to get the bytes
        match state.service.store().get_bytes(hash).await {
            Ok(bytes) => bytes.len() as u64,
            Err(_) => 0,
        }
    } else {
        0
    };

    Ok(Json(BlobInfo {
        hash: hash.to_string(),
        size,
        exists,
    }))
}

/// Download a blob by hash
async fn download_blob(
    State(state): State<AppState>,
    Path(hash_str): Path<String>,
) -> Result<Response, BlobStoreError> {
    let hash = hash_str.parse::<Hash>().context("Invalid hash format")?;

    let data = state
        .service
        .store()
        .get_bytes(hash)
        .await
        .map_err(|_| BlobStoreError::NotFound(hash.to_string()))?;

    info!("Downloaded blob: {} ({} bytes)", hash, data.len());

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", data.len().to_string())
        .body(axum::body::Body::from(data))
        .unwrap()
        .into_response())
}

/// List all blobs (basic implementation)
async fn list_blobs(_state: State<AppState>) -> Result<Json<Vec<BlobInfo>>, BlobStoreError> {
    // Note: This is a simplified implementation
    // In a real implementation, you'd want to iterate through the store
    // For now, we'll return an empty list as iroh-blobs doesn't expose a simple list method
    warn!("List blobs endpoint not fully implemented");
    Ok(Json(Vec::new()))
}

/// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "zoeyr-blob-store"
    }))
}

/// Create the HTTP router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/upload", post(upload_blob))
        .route("/blob/:hash", get(download_blob))
        .route("/blob/:hash/info", get(get_blob_info))
        .route("/blobs", get(list_blobs))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Start the HTTP server
pub async fn start_server(config: BlobStoreConfig) -> Result<(), BlobStoreError> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create the blob store service
    let service = BlobStoreService::new(config.clone()).await?;
    let state = AppState {
        service: Arc::new(service),
    };

    // Create the router
    let app = create_router(state);

    // Start the server
    let addr = format!("{}:{}", config.host, config.port)
        .parse::<std::net::SocketAddr>()
        .context("Invalid address")?;

    info!("Starting blob store server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_blob_store_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = BlobStoreConfig {
            data_dir: temp_dir.path().to_path_buf(),
            port: 0,
            host: "127.0.0.1".to_string(),
        };

        let service = BlobStoreService::new(config).await.unwrap();
        // The store should be created successfully
        assert!(service.config().data_dir.exists());
    }

    #[tokio::test]
    async fn test_blob_store_config_default() {
        let config = BlobStoreConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 8080);
    }
}
