# Client Storage

SQLite-based client-side storage layer for Zoe with SQLCipher encryption support.

## Overview

The `zoe-client-storage` crate provides secure, encrypted local storage for Zoe messaging clients. It uses SQLite with SQLCipher encryption to ensure message data is protected at rest.

## Features

- **SQLCipher Encryption**: All data is encrypted at rest using SQLCipher
- **Async Interface**: Full async/await support with tokio
- **Message Storage**: Store and retrieve messages with metadata
- **Query Support**: Flexible message querying capabilities
- **Migration System**: Automatic schema migrations using Refinery
- **Performance Optimizations**: WAL mode, connection pooling, and optimized SQLite configuration

## System Dependencies

### Required: SQLCipher

This crate requires SQLCipher to be installed on your system for compilation and testing.

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get install libsqlcipher-dev
```

#### Linux (Fedora/Red Hat)
```bash
sudo dnf install sqlcipher-devel
```

#### Linux (Arch/Manjaro)
```bash
sudo pacman -S sqlcipher
```

#### macOS (Homebrew)
```bash
brew install sqlcipher
```

#### Windows
SQLCipher can be installed via vcpkg or manually. See the [SQLCipher documentation](https://www.zetetic.net/sqlcipher/) for detailed instructions.

## Usage

```rust
use zoe_client_storage::{SqliteMessageStorage, StorageConfig};

// Create storage configuration
let config = StorageConfig {
    database_path: "messages.db".into(),
    enable_wal_mode: true,
    connection_pool_size: 10,
    query_timeout: Duration::from_secs(30),
};

// Initialize storage with encryption key
let encryption_key = [0u8; 32]; // Use a proper 32-byte encryption key
let storage = SqliteMessageStorage::new(config, &encryption_key).await?;

// Store a message
storage.store_message(&message).await?;

// Query messages
let messages = storage.query_messages(query).await?;
```

## Development

### Running Tests

Tests require SQLCipher to be installed (see system dependencies above).

```bash
# Run all tests
cargo test --package zoe-client-storage

# Run with nextest
cargo nextest run --package zoe-client-storage
```

### Database Schema

The crate uses Refinery for database migrations. Schema files are located in `migrations/`.

Current schema includes:
- `messages` table: Core message storage
- `message_metadata` table: Extended message properties
- `storage_stats` table: Storage usage tracking

## Security

- **Encryption**: All data is encrypted using SQLCipher with AES-256
- **Key Management**: Encryption keys must be provided by the application
- **Access Control**: Database access is controlled through the storage interface

## Performance

The storage layer is optimized for mobile and desktop applications:

- **WAL Mode**: Write-Ahead Logging for concurrent read/write operations
- **Connection Pooling**: Efficient database connection management  
- **Index Optimization**: Proper indexing for common query patterns
- **Batch Operations**: Support for bulk message operations

## Error Handling

The crate provides comprehensive error types:

- `StorageError::Database`: SQLite-specific errors
- `StorageError::Encryption`: SQLCipher encryption errors
- `StorageError::Migration`: Schema migration errors
- `StorageError::Io`: File system errors
- `StorageError::Serialization`: Data serialization errors

## License

This project is licensed under MIT OR Apache-2.0.