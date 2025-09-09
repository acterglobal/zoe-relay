# Docker Setup for Zoe Network Services

This directory contains Docker Compose configurations for running the Zoe network services including the relay server, Signal bot, and WhatsApp bot.

## Quick Start

### 1. Configure Environment
```bash
# Copy the example environment file
cp env.example .env

# Edit .env to configure your deployment
# At minimum, set ZOERELAY_EXTERNAL_ADDRESSES to your domain
```

### 2. Choose Which Bots to Run

The system supports running different combinations of bots via Docker Compose profiles:

#### Option A: Run Only the Relay Server (No Bots)
```bash
# Start only relay and Redis
docker-compose up -d zoe-relay zoe-redis
```

#### Option B: Run Relay + Signal Bot Only
```bash
# Set profile in .env file
echo "COMPOSE_PROFILES=signal-bot" >> .env

# Or set it inline
COMPOSE_PROFILES=signal-bot docker-compose up -d
```

#### Option C: Run Relay + WhatsApp Bot Only
```bash
# Set profile in .env file  
echo "COMPOSE_PROFILES=whatsapp-bot" >> .env

# Or set it inline
COMPOSE_PROFILES=whatsapp-bot docker-compose up -d
```

#### Option D: Run All Services (Relay + Both Bots)
```bash
# Set profile in .env file
echo "COMPOSE_PROFILES=signal-bot,whatsapp-bot" >> .env

# Or set it inline
COMPOSE_PROFILES=signal-bot,whatsapp-bot docker-compose up -d
```

### 3. Verify Services are Running
```bash
docker-compose ps
```

### 4. Check Service Health
```bash
# Check all service health
docker-compose ps --format "table {{.Name}}\t{{.Status}}"

# View logs for specific services
docker-compose logs zoe-relay
docker-compose logs zoe-signal-bot  # if enabled
docker-compose logs zoe-wa-bot      # if enabled
```

## Bot Configuration

### Environment Variables for Bot Control

Add these to your `.env` file to control bot behavior:

```bash
# Bot profiles (choose which bots to run)
COMPOSE_PROFILES=signal-bot,whatsapp-bot  # Both bots
# COMPOSE_PROFILES=signal-bot               # Signal only
# COMPOSE_PROFILES=whatsapp-bot             # WhatsApp only
# COMPOSE_PROFILES=                         # No bots (relay only)

# Bot connection settings
MAX_CONNECTION_ATTEMPTS=10
RUST_LOG=info
```

### For Coolify Deployments

When deploying with Coolify, you can:

1. **Set environment variables** in the Coolify dashboard:
   - `COMPOSE_PROFILES=signal-bot` (for Signal bot only)
   - `COMPOSE_PROFILES=whatsapp-bot` (for WhatsApp bot only) 
   - `COMPOSE_PROFILES=signal-bot,whatsapp-bot` (for both bots)
   - Leave `COMPOSE_PROFILES` empty or unset for relay-only deployment

2. **Override in docker-compose** by setting the `COMPOSE_PROFILES` environment variable in your Coolify service configuration.

## Docker Compose Commands

### Start services with specific profiles
```bash
# Start with Signal bot only
COMPOSE_PROFILES=signal-bot docker-compose up -d

# Start with both bots
COMPOSE_PROFILES=signal-bot,whatsapp-bot docker-compose up -d

# Start relay only (no bots)
docker-compose up -d zoe-relay zoe-redis
```

### Stop services
```bash
docker-compose down
```

### View logs
```bash
# All services
docker-compose logs

# Specific service
docker-compose logs zoe-relay
docker-compose logs zoe-signal-bot
docker-compose logs zoe-wa-bot
```

### Stop and remove volumes (clears all data)
```bash
docker-compose down -v
```

## Service Configuration

### Relay Server
- **Port**: 13908/udp
- **Health Check**: Automatic UDP connectivity test
- **Data Volume**: `zoe_relay_data` (server keys, blobs)
- **Shared Volume**: `zoe_shared_keys` (public key export)

### Signal Bot (Optional)
- **Profile**: `signal-bot`
- **Health Check**: HTTP health endpoint on port 8080
- **Data Volume**: `signal_bot_data` (Signal database)
- **Dependencies**: Requires healthy relay server

### WhatsApp Bot (Optional)  
- **Profile**: `whatsapp-bot`
- **Health Check**: HTTP health endpoint on port 8081
- **Data Volume**: `zoe_wa_bot_data` (WhatsApp database)
- **Dependencies**: Requires healthy relay server

### Redis
- **Port**: 6379 (internal only)
- **Health Check**: Redis ping command
- **Data Volume**: `zoe_redis_data` (message storage)

## Development Setup

For development, use the separate development compose file:

```bash
# Start only Redis for development
docker-compose -f docker-compose.dev.yml up -d

# Run relay server with cargo
cargo run --package relay
```

## Troubleshooting

### Services won't start
```bash
# Check if required ports are available
sudo lsof -i :13908  # Relay port
sudo lsof -i :6379   # Redis port

# Check container logs
docker-compose logs <service-name>
```

### Bot connection issues
```bash
# Verify relay is healthy
docker-compose ps zoe-relay

# Check relay logs
docker-compose logs zoe-relay

# Verify shared key file exists
docker-compose exec zoe-relay ls -la /shared/keys/
```

### Clear all data and start fresh
```bash
docker-compose down -v
docker-compose up -d
```

### Profile-specific troubleshooting
```bash
# Check which services are defined for current profiles
docker-compose config --services

# Check which profiles are active
echo $COMPOSE_PROFILES
``` 