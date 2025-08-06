# Testing Quick Reference

## 🚀 Essential Commands

### Run All Tests
```bash
# With nextest (recommended)
cargo nextest run --all

# With standard cargo
cargo test --workspace
```

### Run Specific Crate
```bash
cargo nextest run --package zoe-client-storage
cargo test --package zoe-client-storage
```

## 🔧 System Dependencies

### SQLCipher (Required for client-storage tests)

**Linux (Ubuntu/Debian)**:
```bash
sudo apt-get install libsqlcipher-dev
```

**Linux (Fedora/Red Hat)**:
```bash
sudo dnf install sqlcipher-devel
```

**Linux (Arch/Manjaro)**:
```bash
sudo pacman -S sqlcipher
```

**macOS (Homebrew)**:
```bash
brew install sqlcipher
```

**Windows**: See [SQLCipher documentation](https://www.zetetic.net/sqlcipher/) for installation instructions.

### Redis (Required for integration tests)
```bash
# Start Redis with Docker
docker-compose up -d redis

# Or install locally
sudo systemctl start redis
```

## 📋 Nextest Profiles

```bash
# Default profile (4 threads)
cargo nextest run --all

# CI profile (fail-fast=false, retries=2)
cargo nextest run --profile ci --all

# Fast profile (8 threads for quick feedback)
cargo nextest run --profile fast --all
```

## 🐛 Quick Troubleshooting

- **SQLCipher errors**: Install system SQLCipher libraries (see above)
- **Redis connection errors**: Start Redis with `docker-compose up -d redis`
- **Test failures**: Run with `RUST_BACKTRACE=1` for detailed errors

## 📚 Detailed Information

For comprehensive testing guidelines, see **[docs/testing.md](docs/testing.md)**.