# Zoe Blob Store

A content-addressable blob store based on iroh-blobs, exposed via both HTTP REST API and tarpc RPC interface for integration with the QUIC transport layer.

## Features

- Content-addressable storage using iroh-blobs
- **HTTP REST API** for web applications and direct access
- **tarpc RPC interface** for integration with QUIC relay system
- File system-based storage backend
- Automatic deduplication (same content = same hash)
- CORS support for web applications

## Interfaces

### HTTP REST API

Traditional REST endpoints for web integration:

```bash
# Upload a blob
curl -X POST http://localhost:8080/upload \
  -H "Content-Type: application/json" \
  -d '{"name": "test.txt"}' \
  --data-binary @test.txt

# Download a blob
curl http://localhost:8080/blob/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi
```

### tarpc RPC Interface

For integration with the QUIC+tarpc ecosystem:

```rust
use zoe_blob_store::BlobServiceImpl;
use zoe_relay::QuicTarpcServer;

// Host blob service over QUIC
let blob_service = BlobServiceImpl::new("./blob-data").await?;
let server = QuicTarpcServer::new(addr, server_key, blob_service.serve());
server.run().await?;
```

## Installation

```bash
# Build the blob store
cargo build --release

# Run the HTTP server
./target/release/zoe-blob-store

# Or use with relay system (see relay documentation)
```

## Usage

### Command Line Options

```bash
zoe-blob-store [OPTIONS]

Options:
  -d, --data-dir <DATA_DIR>    Data directory for storing blobs [default: ./blob-store-data]
  -p, --port <PORT>            Port to bind the server to [default: 8080]
      --host <HOST>            Host address to bind to [default: 127.0.0.1]
  -h, --help                   Print help
  -V, --version                Print version
```

### HTTP API Endpoints

#### Health Check
```http
GET /health
```

Response:
```json
{
  "status": "healthy",
  "service": "zoe-blob-store"
}
```

#### Upload Blob
```http
POST /upload
Content-Type: application/json

{
  "name": "optional-blob-name"
}
```

Body: Raw binary data

Response:
```json
{
  "hash": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
  "size": 1024
}
```

#### Download Blob
```http
GET /blob/{hash}
```

Response: Raw binary data with `Content-Type: application/octet-stream`

#### Get Blob Info
```http
GET /blob/{hash}/info
```

Response:
```json
{
  "hash": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
  "size": 1024,
  "exists": true
}
```

#### List Blobs
```http
GET /blobs
```

Response:
```json
[
  {
    "hash": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
    "size": 1024,
    "exists": true
  }
]
```

### tarpc RPC Interface

The BlobService provides the following RPC methods:

- **`health_check()`** → `BlobResult<BlobHealth>`: Service health status
- **`upload_blob(data: Vec<u8>)`** → `BlobResult<String>`: Upload and get hash
- **`download_blob(hash: String)`** → `BlobResult<Vec<u8>>`: Download by hash
- **`get_blob_info(hash: String)`** → `BlobResult<BlobInfo>`: Get metadata

#### Using the RPC Interface

```rust
use zoe_wire_protocol::BlobServiceClient;
use zoe_relay::RelayClientBuilder;

// Connect via relay
let mut client = RelayClientBuilder::new(server_addr, server_public_key)
    .build()
    .await?;

let blob_client = client.blob_service().await?;

// Upload a blob
let data = b"Hello, World!".to_vec();
let hash = blob_client.upload_blob(data).await??;
println!("Uploaded blob: {}", hash);

// Download the blob
let downloaded = blob_client.download_blob(hash.clone()).await??;
println!("Downloaded {} bytes", downloaded.len());

// Get blob info
let info = blob_client.get_blob_info(hash).await??;
println!("Blob size: {}", info.size);
```

## Examples

### Using curl (HTTP)

```bash
# Upload a file
curl -X POST http://localhost:8080/upload \
  -H "Content-Type: application/json" \
  -d '{"name": "test.txt"}' \
  --data-binary @test.txt

# Download a blob
curl http://localhost:8080/blob/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi

# Get blob info
curl http://localhost:8080/blob/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/info
```

### Using JavaScript (HTTP)

```javascript
// Upload a blob
const file = new File(['Hello, World!'], 'hello.txt', { type: 'text/plain' });
const response = await fetch('http://localhost:8080/upload', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ name: 'hello.txt' }) + '\n' + await file.text()
});

const { hash } = await response.json();
console.log('Uploaded blob hash:', hash);

// Download a blob
const blobResponse = await fetch(`http://localhost:8080/blob/${hash}`);
const blob = await blobResponse.blob();
console.log('Downloaded blob size:', blob.size);
```

### Using Rust (RPC)

```rust
use zoe_blob_store::BlobServiceImpl;

// Direct service usage
let service = BlobServiceImpl::new("./blob-data").await?;

let data = b"Hello, World!".to_vec();
let hash = service.upload_blob(data.clone()).await?;
let downloaded = service.download_blob(hash).await?;

assert_eq!(data, downloaded);
```

## Architecture

The blob store uses iroh-blobs for content-addressable storage, which provides:

- **Content addressing**: Files are identified by their content hash
- **Deduplication**: Identical content gets the same hash
- **Efficient storage**: Content is stored in a structured format
- **Integrity**: Hash verification ensures data integrity

### Dual Interface Design

- **HTTP Layer**: Simple REST API for web applications and direct integration
- **RPC Layer**: tarpc interface for QUIC+RPC ecosystem integration
- **Shared Backend**: Both interfaces use the same iroh-blobs storage
- **Unified Data**: Blobs uploaded via HTTP are accessible via RPC and vice versa

## Integration Modes

### Standalone HTTP Server

```bash
cargo run --bin zoe-blob-store
```

### Integrated with Relay System

```rust
use zoe_relay::RelayServerBuilder;

let (server, _) = RelayServerBuilder::new(addr)
    .with_redis_url("redis://localhost:6379".to_string())
    .with_blob_storage("./blob-data".to_string())  // Enable blob service
    .build()
    .await?;
```

### Direct RPC Service

```rust
use zoe_relay::QuicTarpcServer;
use zoe_blob_store::BlobServiceImpl;

let blob_service = BlobServiceImpl::new("./blob-data").await?;
let server = QuicTarpcServer::new(addr, server_key, blob_service.serve());
```

## Development

### Building

```bash
cargo build
```

### Testing

```bash
cargo test
```

### Running in Development

```bash
# HTTP server
cargo run -- --port 8080 --host 127.0.0.1

# With relay system
cargo run --example relay_server --package zoe-relay
```

## Error Handling

### HTTP Errors

- `400 Bad Request`: Invalid upload request
- `404 Not Found`: Blob not found
- `500 Internal Server Error`: Storage errors

### RPC Errors

```rust
use zoe_wire_protocol::BlobError;

match blob_client.download_blob(hash).await {
    Ok(Ok(data)) => println!("Downloaded {} bytes", data.len()),
    Ok(Err(BlobError::NotFound)) => println!("Blob not found"),
    Ok(Err(BlobError::StorageError(e))) => println!("Storage error: {}", e),
    Err(e) => println!("RPC error: {}", e),
}
```

## Performance

- **Content deduplication**: Identical content stored only once
- **Streaming I/O**: Large blobs handled efficiently
- **Concurrent access**: Multiple clients supported
- **Memory efficient**: Blobs not loaded entirely into memory

## Security

- **Content addressing**: Hash verification prevents tampering
- **QUIC authentication**: RPC interface uses ed25519 mutual TLS
- **Data isolation**: Blobs stored securely on filesystem
- **Access control**: Authentication at transport layer

## License

This project is part of the Zoe workspace and follows the same license terms. 