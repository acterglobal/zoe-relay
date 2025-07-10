# Zoeyr Blob Store

A content-addressable blob store based on iroh-blobs, exposed via HTTP endpoints instead of iroh's QUIC protocol.

## Features

- Content-addressable storage using iroh-blobs
- HTTP REST API for blob operations
- File system-based storage backend
- Automatic deduplication (same content = same hash)
- CORS support for web applications

## Installation

```bash
# Build the blob store
cargo build --release

# Run the server
./target/release/zoeyr-blob-store
```

## Usage

### Command Line Options

```bash
zoeyr-blob-store [OPTIONS]

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
  "service": "zoeyr-blob-store"
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

## Examples

### Using curl

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

### Using JavaScript

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

## Architecture

The blob store uses iroh-blobs for content-addressable storage, which provides:

- **Content addressing**: Files are identified by their content hash
- **Deduplication**: Identical content gets the same hash
- **Efficient storage**: Content is stored in a structured format
- **Integrity**: Hash verification ensures data integrity

The HTTP layer provides a simple REST API for:
- Uploading blobs
- Downloading blobs by hash
- Querying blob metadata
- Health monitoring

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
cargo run -- --port 8080 --host 127.0.0.1
```

## License

This project is part of the Zoeyr workspace and follows the same license terms. 