# Rate Limiting Implementation

This document describes the application-level rate limiting implementation in the auth service.

## Overview

The auth service implements **Redis-based sliding window rate limiting** to protect against:
- Brute force attacks on login
- Account enumeration
- OTP spam
- API abuse
- DDoS attacks

## Architecture

```
Request → Middleware → Rate Limiter → Redis → Allow/Deny
                ↓
          Check Redis
                ↓
         Increment Counter
                ↓
        Check Limit/Window
```

### Algorithm: Sliding Window

The rate limiter uses a **sliding window algorithm** implemented with Redis sorted sets:

1. **Store**: Each request is stored with its timestamp
2. **Window**: Remove entries older than the time window
3. **Count**: Count remaining entries
4. **Decide**: Allow if under limit, deny if over

**Benefits:**
- ✅ Accurate (no sudden resets)
- ✅ Memory efficient
- ✅ Distributed (works with multiple service instances)
- ✅ Fast (Redis operations)

## Configuration

### File: `config.yaml`

```yaml
rate_limit:
  enabled: true  # Set to false to disable

  # Global rate limit (per IP, all endpoints)
  global_limit: 1000         # Max requests per window
  global_window: 60          # Window in seconds

  # Login endpoint
  login_ip_limit: 10         # Max attempts per IP
  login_ip_window: 300       # 5 minutes
  login_email_limit: 5       # Max attempts per email
  login_email_window: 900    # 15 minutes

  # Signup endpoint
  signup_ip_limit: 3         # Max signups per IP
  signup_ip_window: 3600     # 1 hour

  # OTP endpoints
  otp_email_limit: 3         # Max OTP requests per email
  otp_email_window: 300      # 5 minutes

  # ... (see config.example.yaml for full configuration)
```

### Environment Variables

You can override configuration via environment variables:

```bash
export RATE_LIMIT_ENABLED=true
export RATE_LIMIT_GLOBAL_LIMIT=500
export RATE_LIMIT_LOGIN_IP_LIMIT=5
```

## Rate Limits by Endpoint

| Endpoint | Limit By | Max Requests | Window | Reason |
|----------|----------|--------------|--------|--------|
| `POST /auth/login` | IP | 10 | 5 min | Prevent brute force |
| `POST /auth/login` | Email | 5 | 15 min | Prevent credential stuffing |
| `POST /auth/signup` | IP | 3 | 1 hour | Prevent spam signups |
| `POST /auth/request-otp` | Email | 3 | 5 min | Prevent OTP spam |
| `POST /auth/verify-signup` | Email | 10 | 10 min | Allow multiple attempts |
| `POST /auth/refresh` | Token | 10 | 1 min | Prevent token abuse |
| `POST /auth/2fa/setup` | User | 3 | 1 hour | Limit setup attempts |
| `POST /auth/2fa/verify` | Email | 5 | 5 min | Prevent 2FA bypass |
| `GET /auth/me` | User | 100 | 1 min | Authenticated users |
| All endpoints | IP | 1000 | 1 min | Global DDoS protection |

## Response Format

### Allowed Request

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1704067200
Content-Type: application/json

{
  "success": true,
  ...
}
```

### Rate Limited Request

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1704067200
Retry-After: 120
Content-Type: application/json

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Please try again in 120 seconds.",
    "retry_after_seconds": 120,
    "limit": 10,
    "window": "5m0s"
  }
}
```

## Testing

### Manual Testing

Test login rate limit (should block after 10 attempts):

```bash
./scripts/test_rate_limit.sh
```

### Load Testing

Test with 100 concurrent requests:

```bash
./scripts/load_test_rate_limit.sh /api/v1/auth/login 100 10
```

### Using curl

```bash
# Test login rate limit
for i in {1..15}; do
  echo "Request $i:"
  curl -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}' \
    -w "\nHTTP Status: %{http_code}\n" \
    -i | grep -E "(HTTP|X-RateLimit|Retry-After)"
  echo ""
  sleep 1
done
```

Expected output:
- Requests 1-10: `200/401` (allowed)
- Requests 11-15: `429 Too Many Requests` (blocked)

## Monitoring

### Check Rate Limit in Redis

```bash
# Connect to Redis
redis-cli

# View all rate limit keys
KEYS "ratelimit:*"

# Check specific key
ZRANGE "ratelimit:login:ip:192.168.1.1" 0 -1 WITHSCORES

# Check TTL
TTL "ratelimit:login:ip:192.168.1.1"

# Clear rate limit for testing
DEL "ratelimit:login:ip:192.168.1.1"
```

### Logs

Rate limit events are logged with structured fields:

```json
{
  "level": "warn",
  "msg": "Rate limit exceeded",
  "key": "ratelimit:login:email:user@example.com",
  "endpoint": "/api/v1/auth/login",
  "method": "POST",
  "client_ip": "192.168.1.1",
  "limit": 5,
  "window": "15m0s",
  "retry_after": 120,
  "user_agent": "Mozilla/5.0...",
  "time": "2025-01-15T10:30:00Z"
}
```

## Troubleshooting

### Issue: All requests are rate limited immediately

**Cause**: Redis may have stale data or clock skew

**Solution**:
```bash
# Clear all rate limit keys
redis-cli KEYS "ratelimit:*" | xargs redis-cli DEL

# Or restart Redis
docker-compose restart redis
```

### Issue: Rate limiting not working (all requests allowed)

**Possible causes**:

1. **Rate limiting disabled in config**
   ```yaml
   rate_limit:
     enabled: false  # ← Check this
   ```

2. **Redis connection failure**
   - Check logs for Redis errors
   - Rate limiter fails open (allows requests) on Redis errors
   - Verify Redis is running: `redis-cli ping`

3. **High rate limits**
   - Limits may be higher than test load
   - Check configuration values

4. **Multiple service instances with different configs**
   - Ensure all instances share same configuration

### Issue: Redis memory growing unbounded

**Cause**: Rate limit keys not expiring

**Solution**: Keys have automatic TTL (window + 1 minute)

Check memory usage:
```bash
redis-cli INFO memory
```

If memory is high, check for keys without TTL:
```bash
redis-cli KEYS "ratelimit:*" | while read key; do
  ttl=$(redis-cli TTL "$key")
  if [ "$ttl" == "-1" ]; then
    echo "Key without TTL: $key"
  fi
done
```

## Customization

### Add Rate Limiting to New Endpoint

1. **Define config** in `internal/config/config.go`:
   ```go
   type RateLimitConfig struct {
       // ... existing ...
       MyEndpointLimit  int `mapstructure:"my_endpoint_limit"`
       MyEndpointWindow int `mapstructure:"my_endpoint_window"`
   }
   ```

2. **Set defaults** in `config/config.go`:
   ```go
   viper.SetDefault("rate_limit.my_endpoint_limit", 10)
   viper.SetDefault("rate_limit.my_endpoint_window", 60)
   ```

3. **Apply middleware** in `cmd/auth-service/main.go`:
   ```go
   r.Group(func(r chi.Router) {
       r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
           Limit:   rlCfg.MyEndpointLimit,
           Window:  time.Duration(rlCfg.MyEndpointWindow) * time.Second,
           KeyFunc: appMiddleware.IPBasedKey("my-endpoint"),
           Enabled: rlCfg.Enabled,
           Logger:  logger,
       }))

       r.Post("/my-endpoint", myHandler)
   })
   ```

### Custom Key Functions

Create custom rate limit keys:

```go
// Rate limit by user role
func RoleBasedKey(prefix string) func(r *http.Request) string {
    return func(r *http.Request) string {
        role := getRoleFromContext(r.Context())
        return fmt.Sprintf("ratelimit:%s:role:%s", prefix, role)
    }
}

// Rate limit by API key
func APIKeyBasedKey(prefix string) func(r *http.Request) string {
    return func(r *http.Request) string {
        apiKey := r.Header.Get("X-API-Key")
        return fmt.Sprintf("ratelimit:%s:apikey:%s", prefix, hash(apiKey))
    }
}
```

### Multi-Key Rate Limiting

Apply multiple rate limits (all must pass):

```go
r.Use(appMiddleware.MultiKeyRateLimit(rateLimiter, []appMiddleware.RateLimitConfig{
    {
        Limit:   10,
        Window:  5 * time.Minute,
        KeyFunc: appMiddleware.IPBasedKey("login"),
        Enabled: true,
        Logger:  logger,
    },
    {
        Limit:   5,
        Window:  15 * time.Minute,
        KeyFunc: appMiddleware.EmailBasedKey("login"),
        Enabled: true,
        Logger:  logger,
    },
}))
```

## Best Practices

### 1. Fail Open on Errors

The rate limiter **fails open** by default:
- If Redis is down, requests are allowed
- Prevents service outage from Redis issues
- Errors are logged for monitoring

### 2. Layered Defense

Use rate limiting at multiple layers:
- **API Gateway**: Coarse-grained IP limits (future)
- **Application**: Fine-grained business logic limits (✅ implemented)
- **Database**: Connection pooling and query limits

### 3. Whitelist Internal Services

Skip rate limiting for internal traffic:

```go
func isInternalIP(ip string) bool {
    return strings.HasPrefix(ip, "10.") ||
           strings.HasPrefix(ip, "172.16.") ||
           strings.HasPrefix(ip, "192.168.")
}

if isInternalIP(clientIP) {
    // Skip rate limiting
    next.ServeHTTP(w, r)
    return
}
```

### 4. Monitor Rate Limit Violations

Set up alerts for:
- High rate of 429 responses (potential attack)
- Rate limit violations by endpoint
- Unusual patterns (e.g., distributed attack)

### 5. Gradual Rollout

When enabling rate limiting in production:
1. Start with high limits (monitor only)
2. Gradually decrease limits
3. Monitor impact on legitimate users
4. Adjust based on metrics

## Security Considerations

### Bypass Attempts

Attackers may try to bypass rate limiting:

1. **IP Rotation**
   - Use: Distributed proxies, VPN, Tor
   - Mitigation: Email-based limits, CAPTCHA after failures

2. **Header Manipulation**
   - Use: Fake X-Forwarded-For headers
   - Mitigation: Trust only load balancer headers, validate IP format

3. **Credential Stuffing**
   - Use: Different IPs, same email
   - Mitigation: ✅ Email-based limits implemented

4. **Slow Attacks**
   - Use: Stay just under rate limits
   - Mitigation: Implement anomaly detection (future)

### Defense in Depth

Rate limiting is **one layer** of security:
- ✅ Rate limiting (implemented)
- ⚠️ CAPTCHA (future)
- ⚠️ Anomaly detection (future)
- ✅ Account lockout (implemented)
- ✅ Audit logging (implemented)
- ⚠️ IP reputation (future)

## Performance

### Redis Performance

Sliding window algorithm performance:
- **Operations per check**: 3-4 Redis commands (pipelined)
- **Latency**: <1ms (local Redis), <5ms (remote Redis)
- **Memory**: ~100 bytes per request in window
- **Throughput**: 10,000+ checks/second per Redis instance

### Memory Usage

Estimate memory usage:

```
Memory = (Keys × Avg_Entries_Per_Key × Entry_Size)

Example:
- 1000 active IPs
- 10 endpoints
- 5 avg requests per key
- 100 bytes per entry

Memory = 1000 × 10 × 5 × 100 bytes = 5 MB
```

### Optimization Tips

1. **Use Redis Cluster** for high throughput
2. **Adjust window sizes** based on traffic patterns
3. **Monitor Redis latency** (should be <5ms)
4. **Use connection pooling** (already implemented)

## Future Enhancements

- [ ] Add Prometheus metrics for rate limiting
- [ ] Implement distributed rate limiting across multiple Redis instances
- [ ] Add rate limit bypass for verified premium users
- [ ] Implement adaptive rate limiting based on behavior
- [ ] Add CAPTCHA integration after rate limit threshold
- [ ] Create admin dashboard for rate limit monitoring
- [ ] Implement IP reputation scoring
- [ ] Add rate limit exemption for whitelisted IPs/API keys

## References

- [RATE_LIMITING_ARCHITECTURE.md](./RATE_LIMITING_ARCHITECTURE.md) - Detailed architecture guide
- [config.example.yaml](./config.example.yaml) - Configuration reference
- [Redis Sorted Sets](https://redis.io/docs/data-types/sorted-sets/) - Data structure used

---

**Implementation Date**: 2026-05-24
**Version**: 1.0
**Status**: ✅ Production Ready
