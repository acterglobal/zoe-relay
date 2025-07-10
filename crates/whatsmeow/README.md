# WhatsApp Bot - Rust Wrapper for WhatsApp

A Rust wrapper around the Go WhatsApp library (whatsmeow) that provides a safe and ergonomic interface for building WhatsApp bots.

## Overview

This crate provides Rust bindings for the WhatsApp Web API through the popular Go library `whatsmeow`. It allows you to:

- Connect to WhatsApp Web
- Send and receive messages
- Manage contacts and groups
- Handle authentication via QR codes
- Maintain persistent sessions

## Prerequisites

- **Rust** (latest stable version)
- **Go** (version 1.19 or higher)
- **bindgen** dependencies:
  - `libclang-dev` (Ubuntu/Debian) or `clang` (macOS/other)
- **WhatsApp mobile app** for QR code scanning

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
whatsmeow = { path = "../whatsmeow" }
```

## Building the Go Library

The crate depends on a Go shared library (`libwhatsmeow.so`) that needs to be built before using the Rust wrapper.

### Building the Library

1. Navigate to the whatsmeow crate directory:
```bash
cd crates/whatsmeow
```

2. Build the Go shared library:
```bash
go build -buildmode=c-shared -o libwhatsmeow.so whatsmeow.go
```

This will create:
- `libwhatsmeow.so` - The shared library
- `libwhatsmeow.h` - C header file (used by bindgen)

### Verifying the Build

You can verify the library was built correctly:
```bash
ls -la libwhatsmeow.*
file libwhatsmeow.so
```

## Running Examples

### Callback Test (Recommended First)

Before running the full device test, verify that the callback mechanism is working properly:

```bash
cd crates/whatsmeow
LD_LIBRARY_PATH=. cargo run --example callback_test
```

This test verifies that:
- The WhatsApp bot can be created successfully
- Async callbacks between Rust and Go are working
- The library can query connection status
- QR code generation attempts work (may timeout if not authenticated)
- Contact retrieval works (returns empty list if not authenticated)

**Expected Output:**
- ✅ Bot created successfully
- ✅ Connection status callback worked (Status: LoggedOut)
- ⚠️ QR code callback failed with timeout (normal when not authenticated)
- ✅ Contacts callback worked (Got 0 contacts)

### QR Code Test

Test QR code generation specifically:

```bash
cd crates/whatsmeow
LD_LIBRARY_PATH=. cargo run --example qr_test
```

**Expected Output:**
- ✅ Bot created successfully
- ✅ QR code generation successful!
- 📋 QR Code length: 237 characters
- 📱 **Visual QR Code**: A scannable QR code displayed in your terminal
- 🔗 Raw QR data also available for debugging

### Real Device Test

The `real_device_test` example demonstrates connecting to actual WhatsApp servers and requires proper library path configuration. **This test requires user interaction** (pressing Enter and scanning QR codes).

#### Method 1: Using LD_LIBRARY_PATH (Recommended)

```bash
cd crates/whatsmeow
LD_LIBRARY_PATH=. cargo run --example real_device_test
```

**Note**: This test will:
1. Wait for you to press Enter to continue
2. Generate a real QR code from WhatsApp servers
3. Wait for you to scan the QR code with your phone
4. Test the connection and retrieve your contacts/groups

#### Method 2: Installing the Library System-wide

```bash
# Copy to system library directory (requires sudo)
sudo cp libwhatsmeow.so /usr/local/lib/
sudo ldconfig

# Then run normally
cargo run --example real_device_test
```

#### Method 3: Using cargo with explicit library path

```bash
cd crates/whatsmeow
cargo run --example real_device_test
# If you get "cannot open shared object file" error, use Method 1
```

### What the Real Device Test Does

The real device test will:

1. **Create a WhatsApp bot instance**
2. **Generate a QR code** for authentication
3. **Display the QR code** in a scannable format in your terminal
4. **Wait for you to scan** the QR code with your WhatsApp mobile app
5. **Establish connection** to WhatsApp servers
6. **Test basic functionality** like retrieving contacts and groups

### Interactive Testing Process

When you run the real device test:

1. **Prepare your phone**: Have WhatsApp open and ready
2. **Run the test**: The terminal will display a QR code
3. **Scan the QR code**: 
   - Open WhatsApp on your phone
   - Go to Settings → Linked Devices
   - Tap "Link a Device"
   - Scan the QR code displayed in your terminal
4. **Wait for connection**: The test will verify the connection status
5. **Review results**: The test will show your contacts and groups

## Troubleshooting

### Recent Fixes (2024)

✅ **Fixed**: Database schema initialization with foreign key support
✅ **Fixed**: Callback mechanism between Rust and Go  
✅ **Fixed**: Updated whatsmeow library to latest version for current API compatibility
✅ **Fixed**: Proper library path configuration in examples
✅ **Fixed**: QR code generation now works correctly with real WhatsApp servers
✅ **NEW**: Visual QR codes displayed in terminal - no more copying/pasting QR strings!

### "cannot open shared object file" Error

This error occurs when the system can't find `libwhatsmeow.so`. Solutions:

1. **Use LD_LIBRARY_PATH** (easiest):
   ```bash
   cd crates/whatsmeow
   LD_LIBRARY_PATH=. cargo run --example real_device_test
   ```

2. **Check if the library exists**:
   ```bash
   cd crates/whatsmeow
   ls -la libwhatsmeow.so
   ```

3. **Rebuild the library if missing**:
   ```bash
   cd crates/whatsmeow
   go build -buildmode=c-shared -o libwhatsmeow.so whatsmeow.go
   ```

### QR Code Not Scanning

- **New Feature**: QR codes are now displayed as **visual ASCII art** in your terminal that can be scanned directly
- Ensure good lighting when scanning
- Make sure your phone has internet connection
- The QR code expires after ~20 seconds - restart the example if needed
- Try adjusting your terminal font size for better QR code readability
- If the visual QR code is too small, try maximizing your terminal window

### Connection Issues

- Verify internet connection on both computer and phone
- Check if WhatsApp is working normally on your phone
- Try disconnecting and reconnecting
- Restart the example if authentication fails

### Go Build Issues

If you encounter Go build errors:

1. **Update Go modules**:
   ```bash
   cd crates/whatsmeow
   go mod tidy
   go mod download
   ```

2. **Check Go version**:
   ```bash
   go version  # Should be 1.19+
   ```

3. **Clean and rebuild**:
   ```bash
   cd crates/whatsmeow
   rm -f libwhatsmeow.so libwhatsmeow.h
   go build -buildmode=c-shared -o libwhatsmeow.so whatsmeow.go
   ```

## Development

### Build Process

The build process involves:

1. **build.rs** checks for the Go library files
2. If missing, it shows a warning with build instructions
3. **bindgen** generates Rust bindings from the C header
4. **Cargo** links the shared library at runtime

### Features

- `e2e_real_ffi` - Enables real FFI for end-to-end testing
- Default features use mock implementations for unit testing

### Testing

Run all tests:
```bash
cd crates/whatsmeow
cargo test
```

Run with real FFI:
```bash
cd crates/whatsmeow
LD_LIBRARY_PATH=. cargo test --features e2e_real_ffi
```

## Current Status

### ✅ Working Features

- **Library initialization** - Bot creation and database setup
- **Async callbacks** - Communication between Rust and Go
- **Connection status** - Query current authentication state
- **QR code generation** - Generate real QR codes from WhatsApp servers
- **Contact retrieval** - Get contacts list (when authenticated)
- **Group retrieval** - Get groups list (when authenticated)
- **Message sending** - Send text messages (when authenticated)
- **Database persistence** - SQLite session storage with foreign key support

### 🔧 Requires User Interaction

- **Authentication flow** - QR code scanning with mobile app
- **Real device testing** - Interactive examples for end-to-end testing

### 🚀 Ready for Development

The library is now functional and ready for building WhatsApp bots! The callback mechanism works correctly, and all major features are implemented.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Rust Code     │    │   C FFI Layer    │    │   Go Library    │
│   (Safe API)    │◄──►│   (Unsafe FFI)   │◄──►│   (whatsmeow)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ WhatsApp Servers │
                       └──────────────────┘
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure all tests pass
5. Submit a pull request

## Security Notice

⚠️ **Important**: This library connects to real WhatsApp servers and handles your WhatsApp account. Only use it with accounts you own and trust the security of your environment.

- Never share your session data
- Keep your authentication tokens secure
- Use proper error handling in production
- Consider rate limiting to avoid WhatsApp restrictions 