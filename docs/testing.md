# Testing Guide

## 🧪 Test Organization

### Test Categories
- **Unit Tests**: Core functionality in `src/` files with `#[cfg(test)]` modules
- **Integration Tests**: Component interaction in `tests/` directories  
- **Example Tests**: End-to-end functionality in `examples/` directories

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
    }
    
    #[tokio::test]
    async fn test_async_operation() {
        let storage = create_test_storage().await;
        let result = storage.operation().await;
        assert!(result.is_ok());
    }
}
```

## 🔧 Development Workflow

### Quick Development Tests
```bash
# Test only library code (fastest)
cargo test --lib

# Test specific pattern
cargo test storage

# Test with output
cargo test -- --nocapture

# Test with debugging
RUST_LOG=debug cargo test test_name -- --nocapture
```

### Pre-commit Testing
```bash
# Full test suite
cargo nextest run --all

# With quality checks
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

## 📊 Nextest Configuration

Our `.config/nextest.toml` defines these profiles:

- **`default`**: Standard development (4 threads)
- **`ci`**: CI-optimized (fail-fast=false, retries=2, slow-timeout handling)
- **`fast`**: Quick feedback (8 threads)

```bash
# Use specific profiles
cargo nextest run --profile ci --all
cargo nextest run --profile fast --package zoe-wire-protocol
```

## 🏗️ Writing Quality Tests

### Naming Conventions
```rust
// Good: Descriptive and clear
#[test]
fn message_creation_with_valid_signature_succeeds() { }

#[test] 
fn invalid_encryption_key_returns_error() { }

// Bad: Vague or unclear
#[test]
fn test_stuff() { }

#[test]
fn works() { }
```

### Test Quality Standards
- **Isolated**: Tests should not depend on each other
- **Deterministic**: Always produce the same result
- **Fast**: Unit tests complete in milliseconds
- **Clear**: Failures provide helpful error messages
- **Comprehensive**: Cover both success and error cases

### Coverage Guidelines
- **Core Logic**: All public functions should have unit tests
- **Error Paths**: Test error conditions and edge cases  
- **Integration**: Test component interactions
- **Examples**: Ensure examples compile and demonstrate features

## 🐛 Debugging Test Failures

### Environment Setup
```bash
# Enable detailed logging
export RUST_LOG=debug

# Enable backtrace on panic
export RUST_BACKTRACE=1

# Run with full output
cargo test -- --nocapture
```

### Common Issues

**SQLCipher Compilation Errors**:
- Install system SQLCipher libraries (see main TESTING.md)
- Ensure development headers are available

**Redis Connection Failures**:
```bash
# Check Redis status
docker-compose ps redis

# View Redis logs  
docker-compose logs redis

# Reset Redis
docker-compose restart redis
```

**Async Test Issues**:
- Use `#[tokio::test]` for async tests
- Ensure proper await usage
- Check for deadlocks in concurrent tests

**Flaky Tests**:
- Use `serial_test::serial` for tests requiring sequential execution
- Add proper cleanup in test teardown
- Avoid hardcoded timeouts

## 🚀 Advanced Testing

### Performance Testing
```bash
# Release mode tests (for benchmarks)
cargo test --release

# Specific test timing
cargo nextest run --profile fast test_name
```

### Parallel Execution Control
```bash
# Limit test threads (for debugging)
cargo test -- --test-threads=1

# Run ignored tests
cargo test -- --ignored

# List tests without running
cargo test -- --list
```

### Memory and Resource Testing
```bash
# With Valgrind (Linux)
valgrind --tool=memcheck cargo test

# Memory profiling
cargo test --release --features=profiling
```

## 📈 Best Practices

### Test Data Management
- Use `tempfile` crate for temporary files
- Clean up resources in test teardown
- Use deterministic test data when possible

### Async Testing
- Prefer `tokio::test` over manual runtime creation
- Use `tokio::test(flavor = "multi_thread")` for concurrent tests
- Test timeout scenarios with `tokio::time::timeout`

### Error Testing
```rust
#[test]
fn invalid_input_returns_proper_error() {
    let result = function_with_validation(invalid_input);
    
    assert!(result.is_err());
    match result.unwrap_err() {
        MyError::InvalidInput(msg) => {
            assert_eq!(msg, "Expected error message");
        }
        _ => panic!("Wrong error type"),
    }
}
```

### Integration Test Organization
```rust
// tests/integration_test.rs
use common::setup_test_environment;

mod common;

#[tokio::test]
async fn full_workflow_integration() {
    let env = setup_test_environment().await;
    
    // Test complete user workflow
    let result = env.run_complete_flow().await;
    
    assert!(result.is_ok());
    env.cleanup().await;
}
```

## 🔍 Test Maintenance

### Regular Maintenance
- Remove obsolete tests when refactoring
- Update test data when APIs change
- Ensure tests reflect current business logic
- Monitor test execution time and optimize slow tests

### Documentation
- Comment complex test setups
- Explain what behavior is being tested
- Document any special requirements or dependencies