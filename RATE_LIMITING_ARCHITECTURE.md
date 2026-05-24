# Rate Limiting Architecture Guide

## Overview

This document explains the **layered rate limiting strategy** for the auth service, combining both API Gateway and application-level rate limiting for optimal security and performance.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         Internet                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │     LAYER 1: API Gateway             │
        │  (Infrastructure Rate Limiting)      │
        │                                      │
        │  Purpose: DDoS Protection            │
        │  Based on: IP Address, API Key       │
        │  Limits: Aggressive, simple          │
        │                                      │
        │  Examples:                           │
        │  • 1000 req/min per IP               │
        │  • 100 req/sec burst                 │
        │  • Block known bad IPs               │
        └──────────┬───────────────────────────┘
                   │ ✅ Valid traffic passes
                   │
                   ▼
        ┌──────────────────────────────────────┐
        │    LAYER 2: Auth Service             │
        │  (Business Logic Rate Limiting)      │
        │                                      │
        │  Purpose: Business rule enforcement  │
        │  Based on: User ID, Role, Endpoint   │
        │  Limits: Fine-grained, contextual    │
        │                                      │
        │  Examples:                           │
        │  • 5 login attempts per email        │
        │  • 3 OTP requests per 5min           │
        │  • Premium users: 2x limits          │
        │  • Admin endpoints: stricter         │
        └──────────────────────────────────────┘
```

---

## Layer 1: API Gateway Rate Limiting

### Purpose
**Infrastructure-level protection** against DDoS, brute force, and resource exhaustion.

### Characteristics
- **Coarse-grained**: Simple rules based on IP, headers
- **Fast**: Blocks bad traffic before it reaches services
- **Shared**: Protects all services behind the gateway
- **Resource-efficient**: Prevents wasted compute on malicious traffic

### Implementation Options

#### Option 1: NGINX (Recommended for Self-Hosted)

**Configuration:**
```nginx
# /etc/nginx/nginx.conf

http {
    # Define rate limit zones
    limit_req_zone $binary_remote_addr zone=global:10m rate=100r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=20r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    # Connection limits
    limit_conn_zone $binary_remote_addr zone=addr:10m;

    upstream auth_service {
        least_conn;
        server auth-service-1:8080 max_fails=3 fail_timeout=30s;
        server auth-service-2:8080 max_fails=3 fail_timeout=30s;
        server auth-service-3:8080 max_fails=3 fail_timeout=30s;
    }

    server {
        listen 80;
        server_name auth.yourdomain.com;

        # Global rate limit (all endpoints)
        limit_req zone=global burst=200 nodelay;
        limit_conn addr 10;  # Max 10 concurrent connections per IP

        # Auth endpoints get more restrictive limits
        location /api/v1/auth {
            limit_req zone=auth burst=30 nodelay;
            proxy_pass http://auth_service;
        }

        # Login endpoint - most restrictive
        location /api/v1/auth/login {
            limit_req zone=login burst=3 nodelay;
            proxy_pass http://auth_service;

            # Return 429 with custom message
            limit_req_status 429;
        }

        # Signup endpoint
        location /api/v1/auth/signup {
            limit_req zone=login burst=3 nodelay;
            proxy_pass http://auth_service;
        }

        # OTP endpoints
        location /api/v1/auth/request-otp {
            limit_req zone=login burst=2 nodelay;
            proxy_pass http://auth_service;
        }

        # Health check - no rate limit
        location /health {
            access_log off;
            proxy_pass http://auth_service;
        }

        # Metrics - restrict to internal only
        location /metrics {
            allow 10.0.0.0/8;  # Internal network
            deny all;
            proxy_pass http://auth_service;
        }

        # Block known bad user agents
        if ($http_user_agent ~* (bot|crawler|spider|scraper)) {
            return 403;
        }

        # Security headers
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
    }
}
```

**Rate Limit Zones Explained:**
```
limit_req_zone $binary_remote_addr zone=global:10m rate=100r/s;
                      ↑                    ↑        ↑         ↑
                      |                    |        |         |
                Key (IP address)     Zone name   Memory   Rate limit
                                                  10MB     100 req/sec
```

**Burst Explained:**
```
limit_req zone=login burst=3 nodelay;
                       ↑         ↑
                       |         |
            Allow 3 extra     Process immediately
            requests          (don't queue)
```

**Benefits:**
- ✅ Blocks 99% of DDoS traffic at the edge
- ✅ Extremely fast (NGINX is highly optimized)
- ✅ Protects all backend services
- ✅ Low latency overhead (<1ms)

---

#### Option 2: Kong API Gateway

**Configuration (declarative):**
```yaml
# kong.yml

services:
  - name: auth-service
    url: http://auth-service:8080
    routes:
      - name: auth-routes
        paths:
          - /api/v1/auth

plugins:
  # Global rate limiting
  - name: rate-limiting
    config:
      minute: 1000
      policy: redis
      redis_host: redis
      redis_port: 6379
      fault_tolerant: true

  # Login endpoint - stricter
  - name: rate-limiting
    route: auth-login
    config:
      minute: 5
      hour: 50
      policy: redis

  # Request size limiting (prevent large payloads)
  - name: request-size-limiting
    config:
      allowed_payload_size: 1  # 1 MB

  # IP restriction (whitelist/blacklist)
  - name: ip-restriction
    config:
      deny:
        - 192.168.1.100  # Known bad IP
```

**Benefits:**
- ✅ More flexible than NGINX
- ✅ Built-in admin UI
- ✅ Plugin ecosystem
- ✅ Metrics and monitoring built-in

---

#### Option 3: AWS API Gateway

**Configuration:**
```json
{
  "throttle": {
    "burstLimit": 100,
    "rateLimit": 50
  },
  "quota": {
    "limit": 10000,
    "period": "DAY"
  },
  "methodSettings": {
    "/api/v1/auth/login/POST": {
      "throttle": {
        "burstLimit": 5,
        "rateLimit": 2
      }
    },
    "/api/v1/auth/signup/POST": {
      "throttle": {
        "burstLimit": 3,
        "rateLimit": 1
      }
    }
  }
}
```

**Benefits:**
- ✅ Fully managed (no infrastructure)
- ✅ Integrates with AWS WAF (advanced DDoS protection)
- ✅ Pay-per-use pricing
- ✅ Auto-scaling

---

#### Option 4: Kubernetes Ingress NGINX

**Configuration:**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-service-ingress
  annotations:
    # Rate limiting
    nginx.ingress.kubernetes.io/limit-rps: "100"
    nginx.ingress.kubernetes.io/limit-burst-multiplier: "2"

    # Connection limits
    nginx.ingress.kubernetes.io/limit-connections: "10"

    # Whitelist (optional)
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,192.168.0.0/16"

spec:
  rules:
    - host: auth.yourdomain.com
      http:
        paths:
          - path: /api/v1/auth
            pathType: Prefix
            backend:
              service:
                name: auth-service
                port:
                  number: 8080
```

---

### Recommended Gateway Limits

```yaml
# Global (all endpoints)
rate: 1000 requests/minute per IP
burst: 200 requests

# Auth endpoints (/api/v1/auth/*)
rate: 100 requests/minute per IP
burst: 30 requests

# High-risk endpoints (login, signup, password reset)
/api/v1/auth/login:         5 requests/minute per IP
/api/v1/auth/signup:        3 requests/hour per IP
/api/v1/auth/request-otp:   10 requests/hour per IP
/api/v1/auth/password/reset: 3 requests/hour per IP

# Burst allowance
login:  burst=3
signup: burst=1
```

**Rationale:**
- **IP-based**: Simple, fast, protects infrastructure
- **Aggressive**: Better to block legitimate traffic occasionally than allow attacks
- **Burst**: Allows brief traffic spikes (e.g., page refresh)

---

## Layer 2: Application Rate Limiting (Auth Service)

### Purpose
**Business-logic-aware rate limiting** with fine-grained control based on user behavior, authentication state, and roles.

### Characteristics
- **Fine-grained**: Per-user, per-endpoint, per-method
- **Context-aware**: Knows user ID, roles, subscription tier
- **Business rules**: Enforces domain-specific constraints
- **Complementary**: Works with gateway layer

### Why Application-Level Rate Limiting?

#### Problem 1: IP-Based Limitations
```
Scenario: Corporate office with 500 employees behind single NAT IP

Gateway: "This IP made 600 login attempts in 1 hour - BLOCKED"
Reality: 500 legitimate users each logging in normally

❌ Gateway can't distinguish between users behind same IP
✅ Application can track by user_id/email
```

#### Problem 2: Different User Tiers
```
Free user:    5 API calls/minute
Premium user: 100 API calls/minute
Enterprise:   Unlimited

❌ Gateway doesn't know user subscription tier
✅ Application has full user context
```

#### Problem 3: Complex Business Rules
```
Rule: "After 3 failed login attempts for email X, require CAPTCHA"

❌ Gateway doesn't track login attempts per email
✅ Application can implement this logic
```

---

### Implementation in Auth Service

#### 1. Redis-Based Rate Limiter

**Create Rate Limiter:**
```go
// internal/ratelimit/rate_limiter.go

package ratelimit

import (
    "context"
    "fmt"
    "time"

    "github.com/redis/go-redis/v9"
)

type RateLimiter struct {
    redis *redis.Client
}

func NewRateLimiter(redis *redis.Client) *RateLimiter {
    return &RateLimiter{redis: redis}
}

// Algorithm: Token Bucket (sliding window)
func (r *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
    now := time.Now()
    windowStart := now.Add(-window).Unix()

    pipe := r.redis.Pipeline()

    // Remove old entries outside window
    pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart))

    // Count requests in current window
    pipe.ZCard(ctx, key)

    // Add current request
    pipe.ZAdd(ctx, key, redis.Z{
        Score:  float64(now.Unix()),
        Member: now.UnixNano(), // Unique member
    })

    // Set expiration
    pipe.Expire(ctx, key, window+time.Minute)

    results, err := pipe.Exec(ctx)
    if err != nil {
        return false, err
    }

    // Get count from ZCard result
    count := results[1].(*redis.IntCmd).Val()

    // Allow if under limit
    return count < int64(limit), nil
}

// Get remaining calls
func (r *RateLimiter) Remaining(ctx context.Context, key string, limit int, window time.Duration) (int, error) {
    now := time.Now()
    windowStart := now.Add(-window).Unix()

    count, err := r.redis.ZCount(ctx, key, fmt.Sprintf("%d", windowStart), "+inf").Result()
    if err != nil {
        return 0, err
    }

    remaining := limit - int(count)
    if remaining < 0 {
        remaining = 0
    }

    return remaining, nil
}

// Get reset time
func (r *RateLimiter) ResetAt(ctx context.Context, key string, window time.Duration) (time.Time, error) {
    // Get oldest entry in window
    results, err := r.redis.ZRangeWithScores(ctx, key, 0, 0).Result()
    if err != nil || len(results) == 0 {
        return time.Now().Add(window), nil
    }

    oldestTimestamp := int64(results[0].Score)
    resetTime := time.Unix(oldestTimestamp, 0).Add(window)

    return resetTime, nil
}
```

---

#### 2. Rate Limiting Middleware

**Create Middleware:**
```go
// internal/app/middleware/rate_limit.go

package middleware

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/arafat-hasan/auth1/internal/ratelimit"
)

type RateLimitConfig struct {
    Limit  int
    Window time.Duration
    KeyFunc func(r *http.Request) string
}

func RateLimit(limiter *ratelimit.RateLimiter, config RateLimitConfig) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()

            // Generate rate limit key
            key := config.KeyFunc(r)

            // Check rate limit
            allowed, err := limiter.Allow(ctx, key, config.Limit, config.Window)
            if err != nil {
                // On error, allow request (fail open)
                // Log error for monitoring
                next.ServeHTTP(w, r)
                return
            }

            if !allowed {
                // Rate limit exceeded
                remaining, _ := limiter.Remaining(ctx, key, config.Limit, config.Window)
                resetAt, _ := limiter.ResetAt(ctx, key, config.Window)

                // Set rate limit headers
                w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", config.Limit))
                w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
                w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt.Unix()))

                // Return 429 Too Many Requests
                w.Header().Set("Content-Type", "application/json")
                w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(resetAt).Seconds())))
                w.WriteHeader(http.StatusTooManyRequests)

                fmt.Fprintf(w, `{
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "Rate limit exceeded. Please try again later.",
                        "retry_after_seconds": %d
                    }
                }`, int(time.Until(resetAt).Seconds()))
                return
            }

            // Add rate limit info headers (informational)
            remaining, _ := limiter.Remaining(ctx, key, config.Limit, config.Window)
            w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", config.Limit))
            w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

            next.ServeHTTP(w, r)
        })
    }
}

// Key generation functions

func IPBasedKey(prefix string) func(r *http.Request) string {
    return func(r *http.Request) string {
        ip := getClientIP(r)
        return fmt.Sprintf("ratelimit:%s:ip:%s", prefix, ip)
    }
}

func EmailBasedKey(prefix string) func(r *http.Request) string {
    return func(r *http.Request) string {
        // Extract email from request body
        email := extractEmailFromRequest(r)
        return fmt.Sprintf("ratelimit:%s:email:%s", prefix, email)
    }
}

func UserBasedKey(prefix string) func(r *http.Request) string {
    return func(r *http.Request) string {
        // Extract user ID from JWT token
        userID := getUserIDFromContext(r.Context())
        return fmt.Sprintf("ratelimit:%s:user:%s", prefix, userID)
    }
}

func CompositeKey(prefix string) func(r *http.Request) string {
    return func(r *http.Request) string {
        ip := getClientIP(r)
        email := extractEmailFromRequest(r)
        return fmt.Sprintf("ratelimit:%s:ip:%s:email:%s", prefix, ip, email)
    }
}

// Helper functions

func getClientIP(r *http.Request) string {
    // Check X-Forwarded-For header (from load balancer)
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        // Take first IP (client IP)
        return strings.Split(xff, ",")[0]
    }

    // Check X-Real-IP header
    if xri := r.Header.Get("X-Real-IP"); xri != "" {
        return xri
    }

    // Fallback to RemoteAddr
    ip, _, _ := net.SplitHostPort(r.RemoteAddr)
    return ip
}

func extractEmailFromRequest(r *http.Request) string {
    // Parse request body to get email
    var body struct {
        Email string `json:"email"`
    }

    // Read and restore body
    bodyBytes, _ := io.ReadAll(r.Body)
    r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

    json.Unmarshal(bodyBytes, &body)
    r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

    return body.Email
}
```

---

#### 3. Apply Rate Limiting to Routes

**In main.go:**
```go
// cmd/auth-service/main.go

func main() {
    // ... existing setup ...

    // Create rate limiter
    rateLimiter := ratelimit.NewRateLimiter(redisClient)

    // ── HTTP router ───────────────────────────────────────────────────────────
    r := chi.NewRouter()

    // ... existing middleware ...

    // Global rate limit (per IP)
    r.Use(middleware.RateLimit(rateLimiter, middleware.RateLimitConfig{
        Limit:  1000,
        Window: time.Minute,
        KeyFunc: middleware.IPBasedKey("global"),
    }))

    r.Route("/api/v1/auth", func(r chi.Router) {
        // Login endpoint - dual rate limiting (IP + email)
        r.Group(func(r chi.Router) {
            // Rate limit by IP: 10 attempts per 5 minutes
            r.Use(middleware.RateLimit(rateLimiter, middleware.RateLimitConfig{
                Limit:  10,
                Window: 5 * time.Minute,
                KeyFunc: middleware.IPBasedKey("login"),
            }))

            // Rate limit by email: 5 attempts per 15 minutes
            r.Use(middleware.RateLimit(rateLimiter, middleware.RateLimitConfig{
                Limit:  5,
                Window: 15 * time.Minute,
                KeyFunc: middleware.EmailBasedKey("login"),
            }))

            r.Post("/login", authHandler.Login)
        })

        // Signup endpoint
        r.Group(func(r chi.Router) {
            r.Use(middleware.RateLimit(rateLimiter, middleware.RateLimitConfig{
                Limit:  3,
                Window: time.Hour,
                KeyFunc: middleware.IPBasedKey("signup"),
            }))

            r.Post("/signup", authHandler.Signup)
        })

        // OTP request endpoint
        r.Group(func(r chi.Router) {
            // 3 OTPs per email per 5 minutes
            r.Use(middleware.RateLimit(rateLimiter, middleware.RateLimitConfig{
                Limit:  3,
                Window: 5 * time.Minute,
                KeyFunc: middleware.EmailBasedKey("otp"),
            }))

            r.Post("/request-otp", authHandler.RequestOTP)
        })

        // Password reset endpoint
        r.Group(func(r chi.Router) {
            r.Use(middleware.RateLimit(rateLimiter, middleware.RateLimitConfig{
                Limit:  3,
                Window: time.Hour,
                KeyFunc: middleware.IPBasedKey("password-reset"),
            }))

            r.Post("/password/reset-request", authHandler.PasswordResetRequest)
        })

        // Authenticated endpoints - rate limit by user ID
        r.Group(func(r chi.Router) {
            r.Use(authMiddleware.Authenticate)

            // 100 requests per minute per user
            r.Use(middleware.RateLimit(rateLimiter, middleware.RateLimitConfig{
                Limit:  100,
                Window: time.Minute,
                KeyFunc: middleware.UserBasedKey("authenticated"),
            }))

            r.Get("/me", authHandler.GetMe)
            r.Post("/2fa/setup", authHandler.Setup2FA)
            r.Post("/2fa/disable", authHandler.Disable2FA)
        })
    })

    // ... rest of setup ...
}
```

---

#### 4. Advanced: User-Tier-Based Rate Limiting

**For different subscription tiers:**
```go
// internal/app/middleware/rate_limit_tiered.go

type TieredRateLimiter struct {
    limiter  *ratelimit.RateLimiter
    userRepo UserRepository
}

func (t *TieredRateLimiter) Middleware() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            userID := getUserIDFromContext(r.Context())

            // Get user's subscription tier
            user, _ := t.userRepo.GetUserByID(r.Context(), userID)

            // Determine rate limit based on tier
            var limit int
            var window time.Duration

            switch user.SubscriptionTier {
            case "free":
                limit = 10
                window = time.Minute
            case "premium":
                limit = 100
                window = time.Minute
            case "enterprise":
                limit = 1000
                window = time.Minute
            default:
                limit = 10
                window = time.Minute
            }

            // Check rate limit
            key := fmt.Sprintf("ratelimit:api:user:%s", userID)
            allowed, _ := t.limiter.Allow(r.Context(), key, limit, window)

            if !allowed {
                http.Error(w, "Rate limit exceeded for your subscription tier", http.StatusTooManyRequests)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

---

## Recommended Rate Limits by Endpoint

### Summary Table

| Endpoint | Gateway Limit | Service Limit | Key |
|----------|---------------|---------------|-----|
| `POST /auth/login` | 5/min per IP | 5/15min per email + 10/5min per IP | IP + Email |
| `POST /auth/signup` | 3/hour per IP | 3/hour per IP | IP |
| `POST /auth/verify-signup` | 10/min per IP | 10/5min per email | Email |
| `POST /auth/request-otp` | 10/hour per IP | 3/5min per email | Email |
| `POST /auth/verify-login` | 20/min per IP | 10/10min per email | Email |
| `POST /auth/refresh` | 100/min per IP | 10/min per token | Token |
| `POST /auth/logout` | 100/min per IP | 50/min per user | User ID |
| `GET /auth/me` | 200/min per IP | 100/min per user | User ID |
| `POST /auth/2fa/setup` | 20/min per IP | 3/hour per user | User ID |
| `POST /auth/2fa/verify` | 10/min per IP | 5/5min per email | Email |
| `POST /auth/password/reset-request` | 3/hour per IP | 3/hour per email | Email |
| `POST /auth/password/reset-verify` | 10/hour per IP | 5/hour per token | Token |

---

## Response Headers

**Standard Rate Limit Headers:**
```
X-RateLimit-Limit: 100        // Max requests in window
X-RateLimit-Remaining: 47     // Remaining requests
X-RateLimit-Reset: 1704067200 // Unix timestamp when limit resets
Retry-After: 120              // Seconds to wait (on 429 only)
```

**Example Response (429 Too Many Requests):**
```json
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1704067200
Retry-After: 120

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "You have exceeded the rate limit for login attempts. Please try again in 2 minutes.",
    "retry_after_seconds": 120,
    "limit": 5,
    "window": "15 minutes",
    "request_id": "req_abc123"
  }
}
```

---

## Monitoring & Alerting

### Prometheus Metrics

```go
// internal/metrics/rate_limit_metrics.go

var (
    RateLimitExceeded = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "rate_limit_exceeded_total",
            Help: "Total number of rate limit violations",
        },
        []string{"endpoint", "key_type"}, // key_type: ip, email, user
    )

    RateLimitChecks = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "rate_limit_checks_total",
            Help: "Total number of rate limit checks",
        },
        []string{"endpoint", "result"}, // result: allowed, denied
    )
)
```

### Alert Rules

```yaml
# prometheus/alerts.yml

groups:
  - name: rate_limiting
    rules:
      - alert: HighRateLimitViolations
        expr: rate(rate_limit_exceeded_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High rate of rate limit violations"
          description: "{{ $value }} violations per second"

      - alert: PossibleDDoSAttack
        expr: rate(rate_limit_exceeded_total{endpoint="/auth/login"}[1m]) > 100
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Possible DDoS attack on login endpoint"
```

---

## Testing Rate Limits

### Manual Testing

**Test login rate limit:**
```bash
# Test IP-based rate limit
for i in {1..20}; do
  echo "Request $i:"
  curl -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}' \
    -w "\nHTTP Status: %{http_code}\n\n"
  sleep 1
done
```

**Expected:**
- Requests 1-10: 401 Unauthorized (invalid credentials)
- Requests 11-20: 429 Too Many Requests (rate limit)

### Load Testing

**Using Apache Bench:**
```bash
# 100 requests, 10 concurrent
ab -n 100 -c 10 -H "Content-Type: application/json" \
   -p login.json \
   http://localhost:8080/api/v1/auth/login
```

**Using k6:**
```javascript
// k6-rate-limit-test.js
import http from 'k6/http';
import { check } from 'k6';

export let options = {
  vus: 10,        // 10 virtual users
  duration: '1m', // Run for 1 minute
};

export default function() {
  let payload = JSON.stringify({
    email: 'test@example.com',
    password: 'password123'
  });

  let params = {
    headers: { 'Content-Type': 'application/json' },
  };

  let res = http.post('http://localhost:8080/api/v1/auth/login', payload, params);

  check(res, {
    'status is 401 or 429': (r) => r.status === 401 || r.status === 429,
    'has rate limit headers': (r) => r.headers['X-Ratelimit-Limit'] !== undefined,
  });
}
```

Run: `k6 run k6-rate-limit-test.js`

---

## Configuration

**config.yaml:**
```yaml
rate_limiting:
  enabled: true

  # Global limits (per IP)
  global:
    limit: 1000
    window: "1m"

  # Endpoint-specific limits
  endpoints:
    login:
      ip_limit: 10
      ip_window: "5m"
      email_limit: 5
      email_window: "15m"

    signup:
      ip_limit: 3
      ip_window: "1h"

    otp:
      email_limit: 3
      email_window: "5m"

  # User tier limits (authenticated endpoints)
  user_tiers:
    free:
      limit: 10
      window: "1m"
    premium:
      limit: 100
      window: "1m"
    enterprise:
      limit: 1000
      window: "1m"
```

---

## Best Practices

### 1. Fail Open, Not Closed
```go
allowed, err := limiter.Allow(ctx, key, limit, window)
if err != nil {
    // Log error but ALLOW request
    logger.WithError(err).Error("Rate limiter error")
    next.ServeHTTP(w, r)
    return
}
```

**Rationale:** Redis outage shouldn't break your entire service.

### 2. Use Composite Keys for Critical Endpoints
```go
// Login: Rate limit by BOTH IP and email
key := fmt.Sprintf("ratelimit:login:ip:%s:email:%s", ip, email)
```

### 3. Monitor Rate Limit Hits
```go
if !allowed {
    metrics.RateLimitExceeded.WithLabelValues(endpoint, keyType).Inc()
    logger.WithFields(logrus.Fields{
        "endpoint": endpoint,
        "key":      key,
        "limit":    limit,
    }).Warn("Rate limit exceeded")
}
```

### 4. Provide Clear Error Messages
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "You have made too many login attempts. Please try again in 2 minutes.",
    "retry_after_seconds": 120
  }
}
```

### 5. Whitelist Internal Traffic
```go
func isInternalIP(ip string) bool {
    return strings.HasPrefix(ip, "10.") ||
           strings.HasPrefix(ip, "172.16.") ||
           strings.HasPrefix(ip, "192.168.")
}

if isInternalIP(clientIP) {
    // Skip rate limiting for internal services
    next.ServeHTTP(w, r)
    return
}
```

---

## Summary

### When to Use Each Layer

**API Gateway Rate Limiting:**
- ✅ DDoS protection
- ✅ Infrastructure-level security
- ✅ Simple IP-based limits
- ✅ Protecting multiple services
- ✅ Burst protection

**Application Rate Limiting:**
- ✅ Business logic enforcement
- ✅ User-specific limits
- ✅ Email/phone-based limits
- ✅ Subscription tier limits
- ✅ Complex rules (e.g., "after 3 failures, require CAPTCHA")

### Recommended Approach

**Use BOTH:**
1. **Gateway**: Aggressive IP-based limits (protect infrastructure)
2. **Application**: Fine-grained business rules (protect accounts)

This provides **defense in depth** and optimal security.

---

**End of Document**
