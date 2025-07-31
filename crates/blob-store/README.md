# Zoe Blob Store

A content-addressable blob storage service based on iroh-blobs, designed for integration with the Zoe relay system via tarpc RPC interface.

## Features

- Content-addressable storage using iroh-blobs v0.93.0
- **tarpc RPC interface** for integration with QUIC relay system
- File system-based storage backend (FsStore)
- Automatic deduplication (same content = same hash)
- Hash-based blob identification and retrieval

## Interface

### tarpc RPC Interface

The blob store is designed to be integrated with the Zoe relay system via tarpc RPC:

```rust
use zoe_blob_store::BlobServiceImpl;
use std::path::PathBuf;

// Create a new blob service
let blob_service = BlobServiceImpl::new(PathBuf::from("./blob-data")).await?;

// Use with Zoe relay system (see relay documentation for integration)
```

## Installation

```bash
# Add to your Cargo.toml
[dependencies]
zoe-blob-store = { path = "../blob-store" }
```

## Usage

### Creating a Blob Service

```rust
use zoe_blob_store::BlobServiceImpl;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new blob service with filesystem storage
    let data_dir = PathBuf::from("./blob-data");
    let blob_service = BlobServiceImpl::new(data_dir).await?;
    
    // Upload a blob
    let data = b"Hello, World!".to_vec();
    let hash = blob_service.upload_blob(tarpc::context::current(), data).await??;
    println!("Uploaded blob: {}", hash);
    
    // Download the blob
    let downloaded = blob_service.download_blob(tarpc::context::current(), hash.clone()).await??;
    if let Some(data) = downloaded {
        println!("Downloaded {} bytes", data.len());
    }
    
    // Get blob info
    let info = blob_service.get_blob_info(tarpc::context::current(), hash).await??;
    if let Some(info) = info {
        println!("Blob size: {} bytes", info.size_bytes);
    }
    
    Ok(())
}
```

### RPC Interface

The `BlobService` trait provides the following methods:

- **`health_check()`** → `BlobResult<BlobHealth>`: Service health status
- **`upload_blob(data: Vec<u8>)`** → `BlobResult<String>`: Upload data and get content hash
- **`download_blob(hash: String)`** → `BlobResult<Option<Vec<u8>>>`: Download by hash
- **`get_blob_info(hash: String)`** → `BlobResult<Option<BlobInfo>>`: Get blob metadata

All methods return `BlobResult<T>` which is `Result<T, BlobError>` from the `zoe-wire-protocol` crate.

## Examples

### Basic Usage

```rust
use zoe_blob_store::BlobServiceImpl;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize service
    let service = BlobServiceImpl::new(PathBuf::from("./blob-data")).await?;
    
    // Upload some data
    let data = b"Hello, World!".to_vec();
    let hash = service.upload_blob(tarpc::context::current(), data.clone()).await??;
    println!("Stored blob with hash: {}", hash);
    
    // Retrieve the data
    let retrieved = service.download_blob(tarpc::context::current(), hash.clone()).await??;
    if let Some(blob_data) = retrieved {
        assert_eq!(data, blob_data);
        println!("Successfully retrieved blob!");
    }
    
    // Check blob info
    let info = service.get_blob_info(tarpc::context::current(), hash).await??;
    if let Some(blob_info) = info {
        println!("Blob size: {} bytes", blob_info.size_bytes);
        println!("Created at: {}", blob_info.created_at);
    }
    
    Ok(())
}
```

## License

This project is part of the Zoe workspace and follows the same license terms. 