# Signal Bot Usage Guide

This guide shows how to use the Zoe Signal Bot to connect your Signal account to the Zoe ecosystem.

## Quick Start

### 1. Build the Signal Bot

```bash
cargo build --release --bin signal-bot
```

### 2. Run the Bot

Simply run the bot without any arguments:

```bash
./target/release/signal-bot
```

The bot will automatically:
- Check if you have a registered Signal account
- If not registered, display a QR code for device linking
- Once linked, start listening for incoming messages

### 3. Link Your Device

When you first run the bot, you'll see output like this:

```
INFO No registered account found, attempting to link device...
INFO Starting device linking process
INFO Generating linking QR code...
INFO Device linking URL generated

█████████████████████████████████████
█████████████████████████████████████
████ ▄▄▄▄▄ █▀█ █▄▀▄▀ ▄▄██ ▄▄▄▄▄ ████
████ █   █ █▀▀▀█ ▀ ▀▀▀ ▀▀█ █   █ ████
████ █▄▄▄█ █▀ █▀▀▄▀▀▀▀▄▀██ █▄▄▄█ ████
████▄▄▄▄▄▄▄█▄▀ ▀▄█ █▄█ █▄█▄▄▄▄▄▄▄████
████▄▄  ▄▄▄  ▄▀▄▄▀▄▀▄▀▄▀▄  ▄▄█▄▀████
████▀▄▀▄▀▄▄▄▀▀▀▀▀▀▀▀▀▀▀▀▀▄▄▄▀▄▀▄▀████
████▄▄▄▄▄▄▄█▄██▄▄▄▄▄▄▄▄▄▄█▄▄▄▄▄▄▄████
████ ▄▄▄▄▄ █▄  ▄▄▄▄▄▄▄▄▄▄█ ▄▄▄▄▄ ████
████ █   █ █▀▀▀█▄▄▄▄▄▄▄▄▄█ █   █ ████
████ █▄▄▄█ █▀ █▀▀▄▀▀▀▀▄▀██ █▄▄▄█ ████
████▄▄▄▄▄▄▄█▄▄▄▄▄▄▄▄▄▄▄▄▄█▄▄▄▄▄▄▄████
█████████████████████████████████████
█████████████████████████████████████

INFO Scan the QR code above with your Signal mobile app to link this device
INFO Waiting for device to be linked...
```

1. Open Signal on your mobile device
2. Go to Settings → Linked devices
3. Tap "Link New Device"
4. Scan the QR code displayed in your terminal
5. The bot will automatically complete the linking process

### 4. Bot Operation

Once linked, the bot will:

```
INFO Device successfully linked!
INFO Account already registered, starting bot...
INFO Starting Signal bot - listening for messages...
INFO Running as: Aci(12345678-1234-1234-1234-123456789abc)
INFO Bot is running. Press Ctrl+C to stop.
INFO Incoming messages will be displayed here:
────────────────────────────────────────────────────────────
```

The bot will now:
- Display incoming messages in real-time
- Respond to messages starting with "echo " by echoing back the text
- Continue running until you stop it with Ctrl+C

## Advanced Usage

### Send Messages

You can send messages from the command line:

```bash
./target/release/signal-bot send --to "12345678-1234-1234-1234-123456789abc" --message "Hello from the bot!"
```

Note: You need to use the recipient's UUID, not their phone number.

### Docker Usage

Run the Signal bot in Docker:

```bash
# Build the image
docker build -f Dockerfile.signal-bot -t zoe-signal-bot .

# Run the bot
docker run -it --rm \
  -v signal_bot_data:/app/data \
  zoe-signal-bot
```

Or use docker-compose:

```bash
docker-compose --profile signal-bot up
```

## Echo Bot Functionality

The bot includes simple echo functionality for testing:

1. Send a message to the bot starting with "echo "
2. The bot will respond with "Echo: [your message]"

Example:
- You send: "echo Hello World!"
- Bot responds: "Echo: Hello World!"

## Data Storage

The bot stores its data in:
- Local mode: `./signal-bot-data/signal-store.db`
- Docker mode: `/app/data/signal-store.db` (persisted in Docker volume)

The database is encrypted and contains:
- Signal account registration information
- Device linking credentials
- Message history (if enabled)

## Troubleshooting

### QR Code Not Scanning

- Make sure your terminal supports Unicode characters
- Try a different terminal or increase font size
- The QR code times out after 5 minutes - restart the bot to generate a new one

### "Not yet registered" Error

This means the bot hasn't been linked to a Signal account yet. Run the bot without arguments to start the linking process.

### Connection Issues

- Check your internet connection
- Ensure Signal servers are accessible
- Try restarting the bot

### Database Issues

If you encounter database corruption:

```bash
# Remove the database to start fresh (you'll need to re-link)
rm -rf signal-bot-data/
```

## Integration with Zoe

The Signal bot is designed to integrate with the broader Zoe ecosystem:

- Messages can be forwarded to Zoe groups
- Group invitations can be sent via Signal
- File sharing between Signal and Zoe networks
- Cross-platform messaging capabilities

For more advanced integration, see the API documentation in `src/lib.rs`.