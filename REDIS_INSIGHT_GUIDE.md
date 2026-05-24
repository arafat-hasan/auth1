# Redis Insight Setup & Usage Guide

**Official Redis GUI Tool** - More powerful than Redis Commander

## Why Redis Insight?

Redis Insight is the **official Redis GUI** from Redis Ltd. with significantly more features than Redis Commander:

### Key Features
- 🔍 **Browser** - Visual key browsing with tree view
- 💻 **CLI** - Built-in Redis CLI with auto-completion
- 📊 **Profiler** - Real-time command monitoring
- 🧠 **Memory Analysis** - See memory usage by key pattern
- 📈 **Slow Log** - Identify slow queries
- 🔄 **Pub/Sub** - Monitor Redis streams and pub/sub
- 📱 **Streams** - Visual stream inspection
- 🎯 **Workbench** - Execute Redis commands with syntax highlighting

## Quick Start

### 1. Start Services
```bash
./scripts/docker-dev.sh
```

### 2. Open Redis Insight
Open browser: **http://localhost:5540**

### 3. First Time Setup (One-Time)
When you first open Redis Insight, you'll need to add your Redis database:

1. Click **"Add Redis Database"**
2. Fill in connection details:
   ```
   Host: redis
   Port: 6379
   Name: Auth Service Local
   ```
3. Click **"Add Redis Database"**

That's it! You're connected.

## Key Features for Auth Service

### 1. Browser - Inspect Keys

**Use Case**: Check JWT blacklist, login attempts, rate limits

**Steps**:
1. Click **"Browser"** in left sidebar
2. Use search to filter keys:
   - `blacklist:jwt:*` - Blacklisted JWT tokens
   - `blacklist:user:*` - User-level blacklists
   - `login_attempts:*` - Login attempt tracking
   - `ratelimit:*` - Rate limit counters

**Example**:
```
blacklist:jwt:abc123def456  → "1"
login_attempts:email:user@example.com → Hash with fields:
  - count: 3
  - first_attempt_at: 1234567890
  - last_attempt_at: 1234567900
```

### 2. CLI - Execute Commands

**Use Case**: Run Redis commands with auto-completion

**Steps**:
1. Click **"Workbench"** in left sidebar
2. Type Redis commands (auto-complete will help)
3. Press `Ctrl+Enter` to execute

**Useful Commands**:
```redis
-- Check all keys
KEYS *

-- Check JWT blacklist
KEYS blacklist:jwt:*
GET blacklist:jwt:abc123

-- Check login attempts (Hash)
HGETALL login_attempts:email:user@example.com
HGET login_attempts:email:user@example.com count

-- Check rate limits (Sorted Set)
ZRANGE ratelimit:login:ip:192.168.1.1 0 -1 WITHSCORES
ZCARD ratelimit:login:ip:192.168.1.1

-- Check if account is locked
HGET login_attempts:email:user@example.com locked_until

-- Memory usage
INFO memory
DBSIZE

-- Slow queries
SLOWLOG GET 10
```

### 3. Profiler - Monitor Real-Time Commands

**Use Case**: See what Redis commands your app is executing

**Steps**:
1. Click **"Profiler"** in left sidebar
2. Click **"Start"**
3. Interact with your Auth Service (login, logout, etc.)
4. Watch commands appear in real-time
5. Click **"Stop"** when done

**What to look for**:
- `EXISTS blacklist:jwt:*` - JWT blacklist checks
- `HINCRBY login_attempts:*` - Failed login tracking
- `ZADD ratelimit:*` - Rate limiting
- `SET otp:*` - OTP generation
- `GET refresh_token:*` - Token validation

### 4. Memory Analysis

**Use Case**: Find which keys are using the most memory

**Steps**:
1. Click **"Analysis Tools"** in left sidebar
2. Click **"Database Analysis"**
3. Click **"Analyze"**
4. Wait for scan to complete
5. View memory usage by key pattern

**Useful for**:
- Identifying memory leaks
- Finding keys that should expire but don't
- Planning memory limits

### 5. Slow Log

**Use Case**: Identify slow Redis commands (>10ms)

**Steps**:
1. Click **"Analysis Tools"** → **"Slow Log"**
2. View slow commands
3. Optimize if needed

**Common slow operations**:
- `KEYS *` (avoid in production!)
- `SCAN` with large datasets
- Complex Lua scripts

## Common Workflows

### Workflow 1: Debug Failed Login Attempts

```redis
-- 1. Find user's login attempts
HGETALL login_attempts:email:user@example.com

-- Output:
-- count: 5
-- first_attempt_at: 1716547200
-- last_attempt_at: 1716547300
-- locked_until: 1716548100

-- 2. Check if locked
HGET login_attempts:email:user@example.com locked_until
-- Returns: 1716548100 (Unix timestamp)

-- 3. Unlock manually (for testing)
DEL login_attempts:email:user@example.com

-- 4. Or just reset count
HSET login_attempts:email:user@example.com count 0
```

### Workflow 2: Check JWT Blacklist

```redis
-- 1. Find all blacklisted tokens
KEYS blacklist:jwt:*

-- 2. Check specific token
GET blacklist:jwt:abc123def456
-- Returns: "1" if blacklisted

-- 3. Check token TTL (time until it expires)
TTL blacklist:jwt:abc123def456
-- Returns: seconds remaining

-- 4. Manually remove from blacklist (testing only)
DEL blacklist:jwt:abc123def456
```

### Workflow 3: Monitor Rate Limiting

```redis
-- 1. Find all rate limit keys
KEYS ratelimit:*

-- 2. Check specific IP's rate limit
ZRANGE ratelimit:login:ip:192.168.1.1 0 -1 WITHSCORES
-- Shows timestamps of requests in the window

-- 3. Count requests in window
ZCARD ratelimit:login:ip:192.168.1.1

-- 4. Remove rate limit (testing)
DEL ratelimit:login:ip:192.168.1.1
```

### Workflow 4: Inspect User-Level Token Blacklist

```redis
-- 1. Check if all user tokens are blacklisted (password change)
GET blacklist:user:550e8400-e29b-41d4-a716-446655440000
-- Returns: Unix timestamp when tokens were invalidated

-- 2. Check TTL
TTL blacklist:user:550e8400-e29b-41d4-a716-446655440000

-- 3. Remove blacklist (testing)
DEL blacklist:user:550e8400-e29b-41d4-a716-446655440000
```

## Tips & Tricks

### 1. Use Tree View for Organized Keys
Redis Insight automatically groups keys by colon (`:`) separator:
```
blacklist/
  ├─ jwt/
  │   ├─ abc123
  │   └─ def456
  └─ user/
      └─ 550e8400...
```

### 2. Bulk Operations
Select multiple keys and perform bulk operations:
- Delete multiple keys
- Export keys
- Set TTL on multiple keys

### 3. Export Data
Export keys to JSON or CSV:
1. Select keys in Browser
2. Click **"Bulk Actions"**
3. Choose **"Export"**
4. Select format (JSON/CSV)

### 4. Performance Monitoring
Use the **Dashboard** for real-time metrics:
- Commands per second
- Memory usage
- Connected clients
- Keyspace hits/misses

### 5. Keyboard Shortcuts
- `Ctrl+Enter` - Execute command (Workbench)
- `Ctrl+F` - Search keys (Browser)
- `Ctrl+K` - Command palette

## Comparison: Redis Insight vs Redis Commander

| Feature | Redis Insight | Redis Commander |
|---------|---------------|-----------------|
| **Browser** | ✅ Tree view, filters | ✅ Basic list |
| **CLI** | ✅ Built-in with auto-complete | ❌ External only |
| **Profiler** | ✅ Real-time monitoring | ❌ None |
| **Memory Analysis** | ✅ Advanced | ❌ None |
| **Slow Log** | ✅ Built-in | ❌ None |
| **Pub/Sub** | ✅ Live monitoring | ❌ None |
| **Streams** | ✅ Visual | ❌ None |
| **Performance** | ✅ Optimized | ⚠️ Slower |
| **UI** | ✅ Modern | ⚠️ Basic |
| **Size** | ~300MB | ~50MB |

## Troubleshooting

### Cannot Connect to Redis

**Problem**: Redis Insight shows "Connection failed"

**Solution**:
```bash
# 1. Check Redis is running
docker-compose ps redis

# 2. Check connection from Redis Insight container
docker-compose exec redis-insight ping redis

# 3. Restart Redis Insight
docker-compose restart redis-insight

# 4. Re-add database in Redis Insight with:
#    Host: redis (not localhost!)
#    Port: 6379
```

### Slow Performance

**Problem**: Redis Insight is slow

**Solutions**:
- Avoid `KEYS *` on large databases (use `SCAN` instead)
- Use key patterns to filter (e.g., `blacklist:*`)
- Limit analysis to specific key patterns
- Close unused connections

### Data Not Updating

**Problem**: Keys don't update in real-time

**Solution**:
- Click refresh button in Browser
- Or enable auto-refresh (Settings → Auto-refresh interval)

## Production Usage

### ⚠️ Security Warning

Redis Insight in docker-compose.yml is configured for **development only**.

**For staging/production**:
1. **Don't expose port 5540** publicly
2. Use SSH tunneling or VPN to access
3. Consider Redis Insight Desktop app instead
4. Enable authentication if exposing

### SSH Tunnel for Remote Redis

If your Redis is on a remote server:

```bash
# Create SSH tunnel
ssh -L 6379:localhost:6379 user@remote-server

# Then in Redis Insight, connect to:
Host: localhost
Port: 6379
```

## References

- [Redis Insight Documentation](https://redis.io/docs/ui/insight/)
- [Redis Commands Reference](https://redis.io/commands/)
- [Redis Data Types](https://redis.io/docs/data-types/)
- [Redis Best Practices](https://redis.io/docs/management/optimization/)

---

**Port**: 5540
**Access**: http://localhost:5540
**Status**: ✅ Production-ready official tool
