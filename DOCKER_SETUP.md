# Docker Setup Guide

This document describes the Docker infrastructure setup for the Auth Service.

## Overview

The Auth Service uses Docker Compose for local development, staging, and production deployments. The infrastructure includes:

- **PostgreSQL 15** - Primary database
- **Redis 7** - In-memory cache for rate limiting, JWT blacklist, session management
- **RabbitMQ 3** - Message broker for email events (outbox pattern)
- **Auth Service** - Go application (port 8080)
- **Redis Insight** - Official Redis GUI (development only, port 5540)

## Architecture

```
┌─────────────────┐
│  Auth Service   │ :8080
│   (Go 1.23)     │
└────────┬────────┘
         │
    ┌────┴─────┬─────────────┬──────────────┐
    │          │             │              │
┌───▼───┐  ┌──▼──┐    ┌─────▼────┐   ┌────▼────┐
│ Redis │  │ PG  │    │ RabbitMQ │   │  Redis  │
│  :6379│  │:5432│    │   :5672  │   │ Insight │
└───────┘  └─────┘    │  :15672  │   │  :5540  │
                      └──────────┘   └─────────┘
```

## Environments

### 1. Development (docker-compose.yml)

**Start services**:
```bash
docker-compose up -d
```

**Access**:
- Auth Service: http://localhost:8080
- Redis Insight: http://localhost:5540
- RabbitMQ Management: http://localhost:15672 (guest/guest)
- PostgreSQL: localhost:5432

**Features**:
- Redis Insight (official Redis GUI) for inspecting keys
- Hot-reload friendly (mount local config)
- No authentication on Redis
- Debug logging enabled
- Auto-migrations with seed data

**Redis Keys to Monitor**:
```bash
# JWT Blacklist
blacklist:jwt:*
blacklist:user:*

# Login Attempts
login_attempts:email:*
login_attempts:phone:*
login_attempts:ip:*

# Rate Limiting
ratelimit:*

# OTP
otp:*

# Sessions
refresh_token:*
```

**View Redis Data**:
1. Open Redis Insight: http://localhost:5540
   - First time: Click "Add Redis Database"
   - Host: `redis`, Port: `6379`
2. Or use CLI:
```bash
docker-compose exec redis redis-cli
> KEYS *
> GET blacklist:jwt:abc123
> HGETALL login_attempts:email:user@example.com
```

### 2. Staging (docker-compose.staging.yml)

**Setup**:
```bash
# 1. Copy environment file
cp .env.staging.example .env.staging

# 2. Edit .env.staging with staging credentials
nano .env.staging

# 3. Start services
docker-compose -f docker-compose.yml -f docker-compose.staging.yml up -d
```

**Features**:
- Password-protected Redis
- AOF persistence enabled
- Restart policies
- Staging seed data included
- Debug logging enabled

### 3. Production (docker-compose.prod.yml)

**Setup**:
```bash
# 1. Copy environment file
cp .env.prod.example .env.prod

# 2. Edit .env.prod with production credentials
nano .env.prod

# 3. Generate secrets
openssl rand -base64 64  # For JWT_SECRET
openssl rand -base64 32  # For REDIS_PASSWORD

# 4. Start services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env.prod up -d
```

**Features**:
- **Security**:
  - Password-protected Redis (required)
  - PostgreSQL SSL required
  - No seed data
  - Info-level logging only
- **Performance**:
  - Resource limits (CPU, Memory)
  - Optimized Redis settings:
    - `maxmemory: 200mb`
    - `maxmemory-policy: allkeys-lru`
  - AOF persistence with `everysec` fsync
  - RDB snapshots at intervals
- **Reliability**:
  - Health checks for all services
  - Restart policies
  - Graceful shutdown

**Required Environment Variables**:
```bash
DATABASE_PASSWORD    # PostgreSQL password
REDIS_PASSWORD       # Redis password
JWT_SECRET          # JWT signing secret
```

## Redis Configuration

### Development
- **Persistence**: AOF enabled
- **Memory**: Unlimited
- **Password**: None
- **Max Connections**: Default

### Staging
- **Persistence**: AOF enabled
- **Memory**: Unlimited
- **Password**: Required
- **Policy**: None

### Production
- **Persistence**: AOF + RDB snapshots
- **Memory**: 200MB with LRU eviction
- **Password**: Required
- **Snapshots**:
  - Every 15 minutes if ≥1 key changed
  - Every 5 minutes if ≥10 keys changed
  - Every 1 minute if ≥10,000 keys changed

### Production Memory Management

With 1M users and full Redis usage:
- **Estimated Memory**: ~4.2 GB (see REDIS_ARCHITECTURE_DESIGN.md)
- **Current Limit**: 200 MB (development/testing)
- **Eviction Policy**: `allkeys-lru` (Least Recently Used)

**To adjust for production scale**:
```yaml
# In docker-compose.prod.yml
command: >
  redis-server
  --maxmemory 4gb              # Increase for 1M users
  --maxmemory-policy allkeys-lru
```

## Common Commands

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f auth-service
docker-compose logs -f redis

# With timestamp
docker-compose logs -f --timestamps redis
```

### Restart Services
```bash
# Restart all
docker-compose restart

# Restart one service
docker-compose restart auth-service
docker-compose restart redis
```

### Stop Services
```bash
# Stop all
docker-compose down

# Stop and remove volumes (WARNING: Deletes data!)
docker-compose down -v
```

### Execute Commands
```bash
# PostgreSQL
docker-compose exec postgres psql -U auth1 -d auth1

# Redis CLI
docker-compose exec redis redis-cli

# Redis with password (staging/prod)
docker-compose exec redis redis-cli -a your_password

# Check Redis info
docker-compose exec redis redis-cli INFO memory
docker-compose exec redis redis-cli INFO stats
```

### Database Migrations
```bash
# Run migrations manually
docker-compose run --rm migrations

# Run only up migrations (no seed)
docker-compose run --rm migrations sh -c "./migrate init && ./migrate up"
```

### Health Checks
```bash
# Check all service health
docker-compose ps

# Check specific service
docker inspect --format='{{json .State.Health}}' auth1-redis-1 | jq
```

## Troubleshooting

### Redis Connection Errors

**Symptom**: `Auth service cannot connect to Redis`

**Solutions**:
```bash
# 1. Check Redis is running
docker-compose ps redis

# 2. Check Redis logs
docker-compose logs redis

# 3. Test connection
docker-compose exec redis redis-cli ping
# Should return: PONG

# 4. Check password (staging/prod)
docker-compose exec redis redis-cli -a ${REDIS_PASSWORD} ping

# 5. Restart Redis
docker-compose restart redis
```

### Redis Memory Issues

**Symptom**: `OOM command not allowed when used memory > 'maxmemory'`

**Solutions**:
```bash
# 1. Check current memory usage
docker-compose exec redis redis-cli INFO memory

# 2. Check eviction policy
docker-compose exec redis redis-cli CONFIG GET maxmemory-policy

# 3. Increase memory limit (production)
# Edit docker-compose.prod.yml and change --maxmemory value

# 4. Clear specific keys manually
docker-compose exec redis redis-cli
> FLUSHDB  # Clear current database (careful!)
> KEYS ratelimit:*  # Find specific keys
> DEL ratelimit:login:ip:192.168.1.1
```

### Redis Persistence Issues

**Symptom**: Data lost after restart

**Solution**:
```bash
# 1. Check if AOF is enabled
docker-compose exec redis redis-cli CONFIG GET appendonly
# Should return: 1

# 2. Check AOF status
docker-compose exec redis redis-cli INFO persistence

# 3. Verify volume is mounted
docker volume ls | grep redis
docker volume inspect auth1_redis_data

# 4. Check file exists
docker-compose exec redis ls -lh /data/
# Should see appendonly.aof
```

### Migration Failures

**Symptom**: Migrations fail on startup

**Solutions**:
```bash
# 1. Check migration logs
docker-compose logs migrations

# 2. Check database connection
docker-compose exec postgres psql -U auth1 -d auth1 -c "SELECT 1"

# 3. Run migrations manually with debug
docker-compose run --rm migrations sh -c "set -x && ./migrate init && ./migrate up"

# 4. Reset database (WARNING: Deletes all data!)
docker-compose down -v
docker-compose up -d
```

## Security Best Practices

### Development
- ✅ No passwords (convenience)
- ✅ Exposed ports (debugging)
- ✅ Seed data (testing)

### Staging
- ✅ Password-protected Redis
- ⚠️ Can use weaker passwords
- ✅ Isolated network
- ⚠️ Can include seed data

### Production
- ✅ Strong passwords (20+ characters)
- ✅ Password-protected Redis
- ✅ PostgreSQL SSL required
- ✅ No seed data
- ✅ Limited ports exposure
- ✅ Resource limits
- ✅ Regular backups
- ✅ Monitoring & alerts

### Generating Strong Passwords
```bash
# Redis password
openssl rand -base64 32

# JWT secret (longer)
openssl rand -base64 64

# Database password
openssl rand -base64 24 | tr -d "=+/" | cut -c1-20
```

## Performance Tuning

### Redis Performance
```bash
# Check slow queries
docker-compose exec redis redis-cli SLOWLOG GET 10

# Monitor real-time commands
docker-compose exec redis redis-cli MONITOR

# Check memory fragmentation
docker-compose exec redis redis-cli INFO memory | grep fragmentation

# Latency monitoring
docker-compose exec redis redis-cli --latency
```

### Database Performance
```bash
# Check slow queries (PostgreSQL)
docker-compose exec postgres psql -U auth1 -d auth1 -c "
  SELECT query, calls, total_time, mean_time
  FROM pg_stat_statements
  ORDER BY mean_time DESC
  LIMIT 10;
"
```

## Monitoring

### Key Metrics to Monitor

**Redis**:
- Memory usage
- Keys count
- Evictions
- Hit/Miss ratio
- CPU usage

**PostgreSQL**:
- Connection count
- Query latency
- Lock waits
- Disk usage

**Auth Service**:
- Request latency
- Error rate
- JWT validation time
- Rate limit violations

### Useful Commands
```bash
# Redis stats
docker-compose exec redis redis-cli INFO stats | grep -E "total_commands_processed|total_connections_received|keyspace_hits|keyspace_misses"

# PostgreSQL connections
docker-compose exec postgres psql -U auth1 -d auth1 -c "SELECT count(*) FROM pg_stat_activity;"

# Docker stats
docker stats auth1-redis-1 auth1-postgres-1 auth1-auth-service-1
```

## Backup & Restore

### Redis Backup
```bash
# Trigger RDB snapshot
docker-compose exec redis redis-cli BGSAVE

# Copy AOF file
docker cp auth1-redis-1:/data/appendonly.aof ./backups/redis-$(date +%Y%m%d).aof

# Copy RDB file
docker cp auth1-redis-1:/data/dump.rdb ./backups/redis-$(date +%Y%m%d).rdb
```

### Redis Restore
```bash
# Stop services
docker-compose down

# Restore AOF file
docker cp ./backups/redis-20260524.aof auth1-redis-1:/data/appendonly.aof

# Start services
docker-compose up -d
```

### PostgreSQL Backup
```bash
# Dump database
docker-compose exec postgres pg_dump -U auth1 -d auth1 > backup-$(date +%Y%m%d).sql

# Dump with compression
docker-compose exec postgres pg_dump -U auth1 -d auth1 | gzip > backup-$(date +%Y%m%d).sql.gz
```

### PostgreSQL Restore
```bash
# Restore database
docker-compose exec -T postgres psql -U auth1 -d auth1 < backup-20260524.sql

# Restore compressed
gunzip -c backup-20260524.sql.gz | docker-compose exec -T postgres psql -U auth1 -d auth1
```

## References

- [Redis Configuration](https://redis.io/docs/management/config/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [PostgreSQL Docker](https://hub.docker.com/_/postgres)
- [Redis Docker](https://hub.docker.com/_/redis)
- [RabbitMQ Docker](https://hub.docker.com/_/rabbitmq)

---

**Last Updated**: 2026-05-24
**Maintainer**: Auth Service Team
