# Zoe Relay Server Deployment Guide

Deploy the Zoe Relay Server using Docker Compose for a complete, production-ready setup with Redis and persistent storage.

## 🚀 Quick Deployment

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- Domain name pointing to your server (for external access)
- Basic understanding of Docker and environment variables

### 1. Clone and Configure

```bash
# Clone the repository
git clone https://github.com/acterglobal/zoe-relay.git
cd zoe-relay

# Copy environment template
cp env.example .env

# Edit configuration
nano .env  # or your preferred editor
```

### 2. Configure Environment Variables

Edit the `.env` file with your settings:

```bash
# Required: Your domain name
ZOERELAY_EXTERNAL_ADDRESSES=relay.yourdomain.com

# Network settings
ZOERELAY_INTERFACE=0.0.0.0
ZOERELAY_PORT=13908
ZOERELAY_NAME=My Zoe Relay Server

# Storage paths (will be created automatically)
ZOE_DATA_PATH=./data
REDIS_DATA_PATH=./redis-data

# Logging
RUST_LOG=info
```

### 3. Deploy

```bash
# Create data directories
mkdir -p data redis-data

# Start the services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f zoe-relay
```

The deployment will:
- Build the Zoe Relay Server from source
- Start Redis with persistent storage
- Auto-generate server keys (saved to `./data/server.key`)
- Display QR code in logs for client connections

### 4. Verify Deployment

```bash
# Quick verification
docker-compose ps

# View relay server logs (including QR code)
docker-compose logs zoe-relay
```

The test script will verify:
- ✅ Docker build succeeds
- ✅ Services start correctly
- ✅ Redis connectivity
- ✅ Server key generation and persistence
- ✅ Port accessibility
- ✅ Restart persistence

## 🔧 Configuration Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ZOERELAY_EXTERNAL_ADDRESSES` | - | The addresses to include in the qrcode e.g. example.hellozoe.app or zoe.example.org:13999 (include the port if not the default 13908) |
| `ZOERELAY_INTERFACE` | `127.0.0.1` | Bind interface (use `0.0.0.0` for production) |
| `ZOERELAY_PORT` | `13908` | Server port |
| `ZOERELAY_NAME` | - | Display name for the server |
| `ZOERELAY_DATA_DIR` | `/app/data` | Container data directory |
| `ZOERELAY_REDIS_URL` | `redis://redis:6379` | Redis connection URL |
| `ZOE_DATA_PATH` | `./data` | Host path for server data |
| `REDIS_DATA_PATH` | `./redis-data` | Host path for Redis data |
| `RUST_LOG` | `info` | Log level (`error`, `warn`, `info`, `debug`, `trace`) |

### Advanced Configuration

#### Multiple Domains
```bash
ZOERELAY_EXTERNAL_ADDRESSES=relay.example.com,backup.example.com:8443,192.168.1.100
```

#### Custom Redis Password
```bash
REDIS_PASSWORD=your-secure-password
```

#### Custom Server Key
```bash
# Generate key first
docker-compose run --rm zoe-relay ./zoe-relay generate-key

# Set in environment (replace \n with actual newlines in .env file)
ZOERELAY_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...
-----END PRIVATE KEY-----
```

## 🔄 Management Commands

### Start/Stop Services
```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart relay server only
docker-compose restart zoe-relay

# View logs
docker-compose logs -f
```

### Key Management
```bash
# Generate new server key
docker-compose run --rm zoe-relay ./zoe-relay generate-key

# Show current server key
docker-compose run --rm zoe-relay ./zoe-relay --show-key

# View server identity from logs
docker-compose logs zoe-relay | grep "Server identity"
```

### Data Management
```bash
# Backup server data
tar -czf zoe-backup-$(date +%Y%m%d).tar.gz data/ redis-data/

# View data directory contents
ls -la data/

# Check Redis data
docker-compose exec redis redis-cli info persistence
```

### Monitoring
```bash
# Enable Redis Commander (web UI)
docker-compose --profile management up -d redis-commander
# Access at http://localhost:8081

# View resource usage
docker-compose top

# Check health status
docker-compose ps
```

## 🌐 Production Deployment

### Domain and DNS Setup

1. **Point your domain** to your server's IP address
2. **Configure firewall** to allow port 13908
3. **Update environment** with your domain:
   ```bash
   ZOERELAY_EXTERNAL_ADDRESSES=relay.yourdomain.com
   ```

### Security Hardening

1. **Set Redis password**:
   ```bash
   REDIS_PASSWORD=your-very-secure-password
   ```

2. **Restrict Redis access**:
   ```bash
   # Remove external Redis port exposure
   # Comment out in docker-compose.yml:
   # ports:
   #   - "${REDIS_EXTERNAL_PORT:-6379}:6379"
   ```

3. **Use persistent server key**:
   ```bash
   # Generate once and set ZOERELAY_PRIVATE_KEY in .env
   docker-compose run --rm zoe-relay ./zoe-relay generate-key
   ```

### Backup Strategy

1. **Automated backups**:
   ```bash
   # Add to crontab
   0 2 * * * cd /path/to/zoe-relay && tar -czf backups/zoe-$(date +\%Y\%m\%d).tar.gz data/ redis-data/
   ```

2. **Critical data**:
   - `data/server.key` - Server identity (most important)
   - `data/blobs/` - Blob storage
   - `redis-data/` - Redis persistence files

### Scaling Considerations

1. **Multiple relay instances**:
   - Use same `ZOERELAY_PRIVATE_KEY` across instances
   - Share Redis instance
   - Use load balancer for external addresses

2. **External Redis**:
   ```bash
   ZOERELAY_REDIS_URL=redis://your-redis-cluster:6379
   ```

## 🔍 Troubleshooting

### Common Issues

#### Services won't start
```bash
# Check logs
docker-compose logs

# Check disk space
df -h

# Check permissions
ls -la data/ redis-data/
```

#### Connection issues
```bash
# Test port accessibility
telnet your-domain 13908

# Check firewall
sudo ufw status

# Verify DNS
nslookup relay.yourdomain.com
```

#### Redis connection errors
```bash
# Test Redis connectivity
docker-compose exec redis redis-cli ping

# Check Redis logs
docker-compose logs redis

# Restart Redis
docker-compose restart redis
```

#### Key generation issues
```bash
# Check data directory permissions
ls -la data/

# Generate key manually
docker-compose run --rm zoe-relay ./zoe-relay generate-key

# Check key file
cat data/server.key
```

### Debug Commands

```bash
# Enter relay container
docker-compose exec zoe-relay bash

# Check relay configuration
docker-compose run --rm zoe-relay ./zoe-relay --help

# Test Redis from relay container
docker-compose exec zoe-relay redis-cli -h redis ping

# View detailed logs
docker-compose logs --tail=100 -f zoe-relay
```

## 📋 Deployment Checklist

- [ ] Docker and Docker Compose installed
- [ ] Repository cloned and `.env` configured
- [ ] `ZOERELAY_EXTERNAL_ADDRESSES` set to your domain
- [ ] Domain DNS pointing to server IP
- [ ] Firewall configured (port 13908 open)
- [ ] Data directories created with proper permissions
- [ ] Services started with `docker-compose up -d`
- [ ] Server key auto-generated (check `data/server.key`)
- [ ] QR code displayed in logs
- [ ] Redis running and accessible
- [ ] Backup strategy implemented

## 🔄 Updates and Maintenance

### Updating the Relay Server

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose build --no-cache zoe-relay
docker-compose up -d

# Check logs
docker-compose logs -f zoe-relay
```

### Maintenance Tasks

```bash
# Clean up old Docker images
docker system prune -f

# Rotate logs
docker-compose logs --no-log-prefix > logs/zoe-relay-$(date +%Y%m%d).log

# Check Redis memory usage
docker-compose exec redis redis-cli info memory

# Backup before updates
tar -czf backup-pre-update-$(date +%Y%m%d).tar.gz data/ redis-data/
```

---

**Need Help?** Check the [main README](README.md) for development setup or create an issue for deployment problems.