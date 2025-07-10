# Testing Guide

## 📊 Current Test Status

### ✅ Test Results Summary
- **Total Tests**: 127+ tests across workspace
- **Passing**: 126+ tests (98%+ success rate)
- **Ignored**: 4 tests (intentionally skipped)
- **Failed**: 0 tests

### 📦 Crate-by-Crate Results
- **zoeyr-wire-protocol**: 39/39 tests passing ✅
- **zoeyr-relay-service**: 5/5 tests passing ✅
- **zoeyr-whatsmeow**: 29/31 tests passing (2 ignored) ✅
- **zoeyr-blob-store**: 2/2 tests passing ✅
- **zoeyr-encrypted-storage**: 12/12 tests passing ✅
- **Other components**: 9/9 and various smaller test suites ✅

## 🚀 Running Tests

### Basic Test Commands

```bash
# Run all tests
cargo test --workspace

# Run tests for specific crate
cargo test --package zoeyr-relay-service
cargo test --package zoeyr-wire-protocol
cargo test --package zoeyr-whatsmeow

# Run with verbose output
cargo test --workspace --verbose

# Run specific test
cargo test test_name

# Run tests matching pattern
cargo test message
```

### Development Workflow

```bash
# Quick smoke test during development
cargo test --lib

# Test before commit
cargo test --workspace

# Test examples compile
cargo build --examples

# Check without running tests
cargo check --workspace
```

## 🧪 Test Categories

### Unit Tests
**Location**: `src/` files with `#[cfg(test)]` modules  
**Coverage**: Core functionality, data structures, algorithms  
**Examples**: Protocol message creation, cryptographic operations, serialization

### Integration Tests  
**Location**: `tests/` directories in each crate  
**Coverage**: Component interaction, API contracts  
**Examples**: Redis storage integration, QUIC connection handling

### Example Tests
**Location**: `examples/` directories  
**Coverage**: End-to-end functionality, user-facing features  
**Examples**: Relay server/client communication, file upload/download

## 🔧 Advanced Testing

### Nextest Integration

The project includes nextest configuration for advanced test execution:

```bash
# Install nextest (if not already installed)
cargo install cargo-nextest

# Run with nextest
cargo nextest run --workspace

# Use specific profiles
cargo nextest run --profile unit       # Fast unit tests
cargo nextest run --profile integration # Integration tests
cargo nextest run --profile ci         # CI-optimized execution
```

### Available Nextest Profiles
- **unit** - Fast unit tests (30s timeout)
- **integration** - Integration tests (120s timeout)
- **redis** - Tests requiring Redis (180s timeout)
- **ci** - CI-optimized (excludes manual tests)
- **quick** - Smoke tests (15s timeout)
- **crypto** - Cryptographic tests (90s timeout)

### Redis-Dependent Tests

Some tests require Redis to be running:

```bash
# Start Redis with Docker
docker-compose up -d redis

# Run Redis-dependent tests
cargo test --package zoeyr-relay-service storage

# Verify Redis is working
docker exec zoeyr-redis redis-cli ping
```

## 🎯 Test Writing Guidelines

### Naming Conventions

```rust
// Unit tests
#[test]
fn test_message_creation() { }

#[test]
fn message_serialization_roundtrip() { }

// Async tests
#[tokio::test]
async fn async_storage_operation() { }

// Integration tests
#[test]
fn integration_redis_storage() { }
```

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_functionality() {
        // Arrange
        let input = create_test_data();
        
        // Act
        let result = function_under_test(input);
        
        // Assert
        assert_eq!(result.status, ExpectedStatus::Success);
        assert!(result.data.is_some());
    }
}
```

### Async Testing

```rust
#[tokio::test]
async fn test_async_operation() {
    let storage = create_test_storage().await;
    let message = create_test_message();
    
    let result = storage.store_message(&message).await;
    
    assert!(result.is_ok());
}
```

## 🐛 Troubleshooting

### Common Issues

#### Redis Connection Errors
```bash
# Check if Redis is running
docker-compose ps redis

# Start Redis if needed
docker-compose up -d redis

# Check Redis logs
docker-compose logs redis
```

#### Compilation Issues
```bash
# Clean build artifacts
cargo clean

# Update dependencies
cargo update

# Check specific crate
cargo check --package zoeyr-wire-protocol
```

#### Test Environment
```bash
# Set log level for debugging
export RUST_LOG=debug

# Run single test with logging
cargo test test_name -- --nocapture

# Run with backtrace on panic
RUST_BACKTRACE=1 cargo test
```

### Performance Issues

```bash
# Run tests in release mode
cargo test --release

# Limit test threads
cargo test -- --test-threads=1

# Run specific slow tests
cargo test --package zoeyr-relay-service integration
```

## 📈 Test Coverage

### Current Coverage Areas

✅ **Core Protocol** - Message creation, serialization, validation  
✅ **Cryptography** - Ed25519 operations, certificate generation  
✅ **Storage** - Redis operations, message persistence  
✅ **Network** - QUIC connections, TLS verification  
✅ **Authentication** - Challenge-response flows  
✅ **Examples** - End-to-end functionality  

### Coverage Gaps

🔄 **Load Testing** - High-throughput scenarios  
🔄 **Error Recovery** - Network failure handling  
🔄 **Security** - Penetration testing, fuzzing  
🔄 **Performance** - Benchmark validation  

## 🚀 Continuous Integration

### GitHub Actions
The project includes CI workflows for:
- Compilation checks across platforms
- Test execution
- Code formatting (rustfmt)
- Linting (clippy)
- Security audits

### Local CI Simulation
```bash
# Run the same checks as CI
cargo check --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

## 🎯 Contributing Tests

### Adding New Tests

1. **Choose the right location**:
   - Unit tests: `src/lib.rs` or module files
   - Integration tests: `tests/` directory
   - Example tests: `examples/` directory

2. **Follow naming conventions**:
   - Descriptive test names
   - Group related tests in modules
   - Use appropriate test attributes

3. **Include proper documentation**:
   - Comment complex test logic
   - Explain what behavior is being tested
   - Document any special setup requirements

### Test Quality Standards

- **Isolated**: Tests should not depend on each other
- **Deterministic**: Tests should always produce the same result
- **Fast**: Unit tests should complete quickly
- **Clear**: Test failures should provide helpful error messages
- **Comprehensive**: Cover both success and failure cases

## 📚 Additional Resources

- **[Development Guide](development.md)** - General development setup
- **[Architecture Overview](architecture.md)** - System design and components
- **[Relay Service Examples](../crates/relay-service/examples/README.md)** - Working examples

## 🔍 Debugging Tests

### Useful Commands

```bash
# Run tests with output
cargo test -- --nocapture

# Run specific test with debugging
RUST_LOG=debug cargo test test_name -- --nocapture

# Show ignored tests
cargo test -- --ignored

# List all tests without running
cargo test -- --list
```

### Test Debugging Tips

1. **Use `println!` or `eprintln!`** for debugging output
2. **Set `RUST_LOG=debug`** for detailed logging
3. **Run tests individually** to isolate issues
4. **Check test setup and teardown** for state conflicts
5. **Use `--nocapture`** to see debug output 