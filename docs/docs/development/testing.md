# Testing Guide

Zoe Relay uses comprehensive testing to ensure reliability and security.

## Test Types

### Unit Tests

Test individual functions and modules:

```bash
cargo test
```

### Integration Tests

Test component interactions:

```bash
cargo test --test integration
```

### End-to-End Tests

Test complete workflows:

```bash
cargo test --test e2e
```

## Running Tests

### All Tests

```bash
cargo test
```

### Specific Package

```bash
cargo test -p zoe-client
```

### Specific Test

```bash
cargo test test_pqxdh_key_exchange
```

### With Output

```bash
cargo test -- --nocapture
```

## Test Configuration

### Environment Variables

Some tests require environment variables:

```bash
export TEST_DATABASE_URL="sqlite::memory:"
export REDIS_URL="redis://localhost:6379"
```

### Test Dependencies

#### Redis (for integration tests)

```bash
# Start Redis server
redis-server

# Or use Docker
docker run -d -p 6379:6379 redis:latest
```

#### Test Database

Tests use in-memory SQLite by default, but you can configure a test database:

```bash
export TEST_DATABASE_URL="sqlite:test.db"
```

## Writing Tests

### Unit Test Example

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_encryption() {
        let key = generate_key();
        let message = "Hello, World!";
        
        let encrypted = encrypt_message(&key, message).unwrap();
        let decrypted = decrypt_message(&key, &encrypted).unwrap();
        
        assert_eq!(message, decrypted);
    }
}
```

### Async Test Example

```rust
#[tokio::test]
async fn test_client_connection() {
    let client = Client::new(test_config()).await.unwrap();
    client.connect().await.unwrap();
    
    assert!(client.is_connected());
}
```

### Property-Based Testing

Using `proptest` for property-based tests:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_serialization_roundtrip(message in any::<Message>()) {
        let serialized = serialize(&message).unwrap();
        let deserialized = deserialize(&serialized).unwrap();
        assert_eq!(message, deserialized);
    }
}
```

## Test Coverage

Generate test coverage reports:

```bash
# Install cargo-tarpaulin
cargo install cargo-tarpaulin

# Generate coverage
cargo tarpaulin --out Html
```

## Benchmarks

Run performance benchmarks:

```bash
cargo bench
```

## Continuous Integration

Tests run automatically on:
- Pull requests
- Pushes to main/develop branches
- Nightly builds

See `.github/workflows/ci.yml` for the complete CI configuration.

## Test Best Practices

1. **Test Naming**: Use descriptive names that explain what is being tested
2. **Test Organization**: Group related tests in modules
3. **Test Data**: Use realistic test data when possible
4. **Assertions**: Use specific assertions with clear error messages
5. **Cleanup**: Ensure tests clean up after themselves
6. **Isolation**: Tests should not depend on each other

## Debugging Tests

### Using `dbg!` Macro

```rust
#[test]
fn test_debug_example() {
    let value = calculate_something();
    dbg!(&value);
    assert_eq!(value, expected);
}
```

### Using Debugger

With VS Code and CodeLLDB:
1. Set breakpoints in test code
2. Run "Debug Test" from the test function
3. Step through code execution

## Mock Testing

For testing external dependencies:

```rust
#[cfg(test)]
mod tests {
    use mockall::predicate::*;
    use super::*;

    #[tokio::test]
    async fn test_with_mock() {
        let mut mock_service = MockExternalService::new();
        mock_service
            .expect_call()
            .with(eq("test"))
            .times(1)
            .returning(|_| Ok("response".to_string()));

        let result = use_service(&mock_service, "test").await;
        assert_eq!(result.unwrap(), "response");
    }
}
```