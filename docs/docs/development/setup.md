# Development Setup

This guide will help you set up your development environment for contributing to Zoe Relay.

## Prerequisites

### Required Tools

- **Rust**: Version 1.85.0 or later
- **Git**: For version control
- **SQLCipher**: For encrypted database support
- **Protobuf Compiler**: For protocol buffer compilation

### System Dependencies

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y libsqlcipher-dev protobuf-compiler cmake build-essential
```

#### macOS
```bash
brew install sqlcipher protobuf cmake
```

#### Windows
Use vcpkg or install dependencies manually.

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/acter/zoe-relay.git
cd zoe-relay
```

### 2. Install Rust Dependencies

```bash
cargo fetch
```

### 3. Build the Project

```bash
cargo build
```

### 4. Run Tests

```bash
cargo test
```

## Development Workflow

### Code Formatting

We use `rustfmt` for consistent code formatting:

```bash
cargo fmt
```

### Linting

Use `clippy` for additional linting:

```bash
cargo clippy
```

### Documentation

Generate and view documentation:

```bash
cargo doc --open
```

## Project Structure

```
zoe-relay/
├── crates/
│   ├── app-primitives/    # Core utilities and primitives
│   ├── client/           # Client library
│   ├── relay/            # Relay server implementation
│   ├── wire-protocol/    # Message formats and serialization
│   └── ...
├── docs/                 # Documentation (this site)
└── target/              # Build artifacts
```

## Environment Variables

Create a `.env` file based on `env.example`:

```bash
cp env.example .env
# Edit .env with your configuration
```

## Running the Relay Server

```bash
cargo run --bin zoe-relay
```

## IDE Setup

### VS Code

Recommended extensions:
- rust-analyzer
- CodeLLDB (for debugging)
- Better TOML

### Other IDEs

The project works with any IDE that supports Rust via rust-analyzer.

## Troubleshooting

### Common Issues

1. **SQLCipher not found**: Ensure libsqlcipher-dev is installed
2. **Protobuf errors**: Install protobuf-compiler
3. **Build failures**: Try `cargo clean` and rebuild

For more help, see the [Contributing Guide](./contributing) or open an issue on GitHub.