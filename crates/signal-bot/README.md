# Zoe Signal Bot

A Signal bot implementation using the [presage](https://github.com/whisperfish/presage) library for Signal protocol communication. This bot provides a command-line interface for Signal messaging with QR code authentication and local encrypted database storage.

## Features

- **QR Code Authentication**: Display QR codes in the terminal for easy device linking
- **Encrypted Storage**: Local database with encryption support using Sled
- **Message Handling**: Send and receive text messages
- **CLI Interface**: Command-line interface for all operations
- **Docker Support**: Ready for containerized deployment
- **Echo Bot**: Simple echo functionality for testing

## Installation

### From Source

```bash
# Clone the repository
git clone <repository-url>
cd zoe-bots-init

# Build the Signal bot
cargo build --release --bin signal-bot

# The binary will be available at target/release/signal-bot
```

### Using Docker

```bash
# Build and run with Docker Compose
docker-compose --profile signal-bot up --build

# Or build the Docker image directly
docker build -f Dockerfile.signal-bot -t zoe-signal-bot .
docker run -it -v signal_data:/app/data zoe-signal-bot
```

## Usage

### First Time Setup

When running the Signal bot for the first time, you'll need to either register a new account or link an existing one:

```bash
# Register a new Signal account (requires phone number)
signal-bot register --phone +1234567890

# Or just run the bot - it will prompt for registration if needed
signal-bot
```

### Device Linking

If you already have a Signal account, the bot will show a QR code for device linking:

```bash
signal-bot register --phone +1234567890
```

1. The bot will display a QR code in your terminal
2. Open Signal on your mobile device
3. Go to Settings → Linked Devices → Link New Device
4. Scan the QR code displayed in the terminal
5. The bot will automatically detect when linking is complete

### Running the Bot

Once registered/linked, start the bot to listen for messages:

```bash
# Run with default data directory (./signal-bot-data)
signal-bot run

# Run with custom data directory
signal-bot --data-dir /path/to/data run

# Run with verbose logging
signal-bot --verbose run
```

### Sending Messages

```bash
# Send a message using phone number
signal-bot send --to +1234567890 --message "Hello from Signal Bot!"

# Send a message using UUID (if you know the recipient's UUID)
signal-bot send --to 550e8400-e29b-41d4-a716-446655440000 --message "Hello!"
```

### CLI Options

```bash
signal-bot --help
```

**Global Options:**
- `--data-dir <PATH>`: Directory for storing encrypted database (default: `signal-bot-data`)
- `--verbose`: Enable verbose logging

**Commands:**
- `register --phone <PHONE>`: Register new account or link existing one
- `run`: Start the bot and listen for messages
- `send --to <RECIPIENT> --message <TEXT>`: Send a message

## Docker Usage

### Using Docker Compose

```bash
# Start the Signal bot service
docker-compose --profile signal-bot up

# View logs
docker-compose --profile signal-bot logs -f zoe-signal-bot

# Stop the service
docker-compose --profile signal-bot down
```

### Manual Docker Usage

```bash
# Build the image
docker build -f Dockerfile.signal-bot -t zoe-signal-bot .

# Run interactively for initial setup
docker run -it -v signal_data:/app/data zoe-signal-bot

# Run in background after setup
docker run -d -v signal_data:/app/data zoe-signal-bot
```

## Configuration

The Signal bot stores its configuration and encrypted database in the data directory:

```
signal-bot-data/
├── signal-store/          # Encrypted Sled database
│   ├── conf
│   ├── db
│   └── snap.*/
└── logs/                  # Application logs (if configured)
```

### Environment Variables

- `RUST_LOG`: Set logging level (e.g., `info`, `debug`, `warn`)
  ```bash
  RUST_LOG=debug signal-bot run
  ```

## Echo Bot Functionality

The bot includes simple echo functionality for testing:

1. Send a message starting with "echo " to the bot
2. The bot will respond with "Echo: [your message]"

Example:
- You send: "echo Hello World"
- Bot responds: "Echo: Hello World"

## Security

- **Encrypted Storage**: All Signal protocol data is stored in an encrypted local database
- **No Cloud Dependencies**: Everything runs locally, no data sent to third parties
- **Signal Protocol**: Uses the same end-to-end encryption as the official Signal app
- **Secure Authentication**: QR code linking uses Signal's secure device linking protocol

## Troubleshooting

### Common Issues

1. **"Phone number is required for registration"**
   - Make sure to provide a phone number: `signal-bot register --phone +1234567890`

2. **"Registration failed"**
   - Ensure the phone number is in international format (+1234567890)
   - Check your internet connection
   - Try again after a few minutes

3. **"Linking timeout"**
   - Make sure to scan the QR code within 5 minutes
   - Ensure your mobile device has internet connection
   - Try generating a new QR code

4. **Database errors**
   - Check that the data directory is writable
   - Ensure sufficient disk space
   - Try deleting the data directory and re-registering (you'll lose message history)

### Logging

Enable verbose logging for debugging:

```bash
RUST_LOG=debug signal-bot --verbose run
```

### Data Directory Issues

If you encounter database corruption:

```bash
# Backup your data directory first
cp -r signal-bot-data signal-bot-data.backup

# Remove corrupted database (you'll need to re-register)
rm -rf signal-bot-data/signal-store

# Re-register
signal-bot register --phone +1234567890
```

## Development

### Building from Source

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone <repository-url>
cd zoe-bots-init
cargo build --release --bin signal-bot
```

### Running Tests

```bash
# Run unit tests
cargo test -p zoe-signal-bot

# Run with output
cargo test -p zoe-signal-bot -- --nocapture

# Run specific test
cargo test -p zoe-signal-bot test_signal_bot_creation
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `cargo test`
6. Submit a pull request

## License

This project is licensed under the same license as the main Zoe project.

## Acknowledgments

- [presage](https://github.com/whisperfish/presage) - Rust Signal client library
- [Signal Protocol](https://signal.org/docs/) - End-to-end encryption protocol
- [Sled](https://github.com/spacejam/sled) - Embedded database for encrypted storage