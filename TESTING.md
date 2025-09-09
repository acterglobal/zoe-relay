# Testing Guide

## Test Categories

### Default Tests (Mock Only)
By default, `cargo nextest run --all` runs only tests that use mocks and don't connect to external services.

```bash
# Run all tests excluding external services (default)
cargo nextest run --all

# Run specific test categories
cargo nextest run --test-group unit
cargo nextest run --test-group integration
```

### External Service Tests

External service tests are disabled by default to avoid:
- Hitting rate limits on external APIs
- Requiring real accounts/credentials
- Network dependencies in CI/CD

#### WhatsApp External Tests
```bash
# Enable WhatsApp external service tests
export WHATSAPP_EXTERNAL_TESTS=1
cargo nextest run --profile whatsapp-external

# Or run all external service tests
cargo nextest run --profile external-services
```

#### Signal External Tests
```bash
# Enable Signal external service tests
export SIGNAL_EXTERNAL_TESTS=1
cargo nextest run --profile signal-external
```

#### All Tests Including External Services
```bash
# Run everything (use with caution)
export WHATSAPP_EXTERNAL_TESTS=1
export SIGNAL_EXTERNAL_TESTS=1
cargo nextest run --profile all-including-external
```

## Environment Variables

- `WHATSAPP_EXTERNAL_TESTS=1` - Enable WhatsApp external service tests
- `SIGNAL_EXTERNAL_TESTS=1` - Enable Signal external service tests

## Test Profiles

- `default` - Mock tests only (safe for CI)
- `ci` - Same as default with retries
- `external-services` - All external service tests
- `whatsapp-external` - WhatsApp external tests only
- `signal-external` - Signal external tests only
- `all-including-external` - Everything including external services

## Running Tests

```bash
# Safe default testing (recommended)
cargo nextest run --all

# Test with external services (requires setup)
WHATSAPP_EXTERNAL_TESTS=1 SIGNAL_EXTERNAL_TESTS=1 cargo nextest run --profile all-including-external

# Test specific external service
WHATSAPP_EXTERNAL_TESTS=1 cargo nextest run --profile whatsapp-external
```

## WhatsApp Bot Testing

The WhatsApp bot uses a feature-based mock system:

### Mock Mode (Default)
- Uses `mock-ffi` feature (enabled by default)
- No real WhatsApp connections
- Returns predictable mock responses
- Safe for CI/CD and development

### Real WhatsApp Mode
- Disable `mock-ffi` feature: `--no-default-features --features e2e-real-ffi`
- Connects to real WhatsApp servers
- Requires phone number and QR code scanning
- Only for manual testing

```bash
# Mock mode (default)
cargo test -p zoe-wa-bot

# Real WhatsApp mode (manual testing only)
cargo test -p zoe-wa-bot --no-default-features --features e2e-real-ffi
```

## Signal Bot Testing

Signal bot tests are designed to work without external services:
- Tests expected failure cases (no registration)
- Uses temporary directories for isolation
- No real Signal connections by default

## Nextest Configuration

The workspace uses `.config/nextest.toml` for test organization:
- 15s timeout for local tests
- 60s timeout for external service tests
- Proper test filtering and grouping
- Parallel execution with appropriate thread limits

## Test Development Guidelines

1. **Default to mocks** - New tests should use mocks by default
2. **External tests** - Mark with `#[ignore]` and environment variable checks
3. **Deterministic** - Tests should be repeatable and not depend on external state
4. **Fast** - Keep test execution time reasonable
5. **Isolated** - Tests should not interfere with each other

## Troubleshooting

### Tests Connecting to External Services
If tests are unexpectedly connecting to external services:
1. Check that `mock-ffi` feature is enabled (default for whatsmeow)
2. Verify environment variables are not set
3. Ensure using the correct nextest profile

### Slow Test Execution
1. Use `cargo nextest run` instead of `cargo test`
2. Check nextest configuration timeouts
3. Consider running specific test groups

### CI/CD Integration
```bash
# Recommended CI command
cargo nextest run --all --profile ci
```

This ensures:
- No external service dependencies
- Appropriate retries for flaky tests
- Fast fail for quick feedback