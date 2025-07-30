# Zoe Relay Server CLI

The Zoe Relay Server CLI provides a command-line interface for running the QUIC relay server with ed25519 authentication.

## Installation

Build the CLI from the relay crate:

```bash
cd crates/relay
cargo build --release --bin zoe-relay
```

The binary will be available at `target/release/zoe-relay`.

## Basic Usage

### Start the server with default settings

```bash
cargo run --bin zoe-relay
```

This starts the server on `127.0.0.1:4433` with blob storage in `./blob-store-data`.

### Generate a new server key

```bash
cargo run --bin zoe-relay -- --generate-key
```

This generates a new ed25519 signing key for the server and prints it in hex format.

### Custom address and blob directory

```bash
cargo run --bin zoe-relay -- --address 0.0.0.0:8443 --blob-dir /var/lib/zoe-blobs
```

### Using a configuration file

```bash
cargo run --bin zoe-relay -- --config config.toml
```

## Command Line Options

- `-a, --address <ADDRESS>` - Server bind address (default: `127.0.0.1:4433`)
- `-c, --config <FILE>` - Configuration file path
- `-b, --blob-dir <DIRECTORY>` - Blob storage directory (default: `./blob-store-data`)
- `--generate-key` - Generate a new server key and exit
- `-h, --help` - Print help information
- `-V, --version` - Print version information

## Configuration File Format

The configuration file uses TOML format:

```toml
# Server signing key (ed25519 in hex format)
server_key = "your_server_key_here"

[blob_config]
# Directory for blob storage
data_dir = "/path/to/blob/storage"
```

## Environment Variables

You can control logging with the `RUST_LOG` environment variable:

```bash
RUST_LOG=info cargo run --bin zoe-relay
RUST_LOG=debug cargo run --bin zoe-relay
```

## Services

The relay server currently supports:
- **Blob Service** (Service ID: 11) - File upload/download operations

## Security

- The server uses ed25519 keys for client authentication
- All communication is secured with QUIC/TLS 1.3
- Client certificates must contain valid ed25519 public keys

## Example: Running in Production

1. Generate a server key:
   ```bash
   ./zoe-relay --generate-key
   ```

2. Create a configuration file:
   ```toml
   server_key = "your_generated_key_here"
   
   [blob_config]
   data_dir = "/var/lib/zoeyr/blobs"
   ```

3. Start the server:
   ```bash
   ./zoe-relay --config production.toml --address 0.0.0.0:4433
   ```

4. Monitor with structured logging:
   ```bash
   RUST_LOG=info ./zoe-relay --config production.toml
   ```

## Graceful Shutdown

The server handles `Ctrl+C` (SIGINT) gracefully and will log shutdown status.