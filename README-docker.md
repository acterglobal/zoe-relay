# Docker Setup for Zoe Relay Service Testing

This directory contains a Docker Compose configuration for running a local Redis instance for testing the Zoe relay service.

## Quick Start

### 1. Start Redis
```bash
docker-compose up -d
```

### 2. Verify Redis is running
```bash
docker-compose ps
```

You should see the `zoe-redis` container running on port 6379.

### 3. Test Redis connection
```bash
docker exec -it zoe-redis redis-cli ping
```

Should return `PONG`.

### 4. Run your relay service tests
```bash
# Build the test binary
cargo build --package zoe-relay-service

# Send test messages
./target/debug/relay-service-test send --count 5 --with-event --with-user

# Listen for messages (in another terminal)
./target/debug/relay-service-test listen --authors "test_author_123"
```

## Docker Compose Commands

### Start services
```bash
docker-compose up -d
```

### Stop services
```bash
docker-compose down
```

### View logs
```bash
docker-compose logs redis
```

### Stop and remove volumes (clears all data)
```bash
docker-compose down -v
```

## Redis Configuration

- **Port**: 6379 (default Redis port)
- **Persistence**: Enabled with AOF (Append Only File)
- **Data Volume**: `redis_data` (persists between container restarts)
- **Health Check**: Automatic ping every 5 seconds

## Connection Details

- **Host**: localhost
- **Port**: 6379
- **URL**: redis://127.0.0.1:6379 (default in your test tool)

## Troubleshooting

### Redis won't start
```bash
# Check if port 6379 is already in use
sudo lsof -i :6379

# Kill any existing Redis processes
sudo pkill redis-server
```

### Can't connect to Redis
```bash
# Check if container is running
docker-compose ps

# Check container logs
docker-compose logs redis

# Restart the container
docker-compose restart redis
```

### Clear all data and start fresh
```bash
docker-compose down -v
docker-compose up -d
``` 