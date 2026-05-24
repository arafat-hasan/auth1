# Redis Architecture Design - Comprehensive Strategy

**Version:** 2.0
**Date:** 2026-05-24
**Status:** Design Review
**Purpose:** Complete Redis utilization strategy for auth service

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Proposed Use Cases](#proposed-use-cases)
4. [Data Structure Design](#data-structure-design)
5. [Key Naming Convention](#key-naming-convention)
6. [TTL & Eviction Strategy](#ttl--eviction-strategy)
7. [Memory Management](#memory-management)
8. [High Availability & Scaling](#high-availability--scaling)
9. [Security Considerations](#security-considerations)
10. [Monitoring & Observability](#monitoring--observability)
11. [Migration Strategy](#migration-strategy)
12. [Implementation Roadmap](#implementation-roadmap)
13. [Future Enhancements](#future-enhancements)

---

## Executive Summary

### Purpose

This document defines a **comprehensive Redis utilization strategy** for the authentication service, transforming Redis from a simple cache into a high-performance operational data store for:
- Rate limiting & abuse prevention
- Session management & token lifecycle
- Temporary state & challenge-response flows
- Distributed coordination

### Key Objectives

1. ✅ **Performance**: Sub-millisecond latency for auth operations
2. ✅ **Scalability**: Support 10M+ active sessions
3. ✅ **Security**: Token revocation, blacklisting, abuse prevention
4. ✅ **Reliability**: High availability, data persistence options
5. ✅ **Cost-Efficiency**: Optimal memory usage, automatic cleanup

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Authentication Service                        │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Handlers   │→ │   Services   │→ │ Redis Client │          │
│  └──────────────┘  └──────────────┘  └──────┬───────┘          │
└─────────────────────────────────────────────┼──────────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │         Redis Cluster / Sentinel                  │
                    │                                                    │
                    │  ┌──────────────────────────────────────────┐    │
                    │  │  Hot Data (In-Memory)                    │    │
                    │  │  • Rate limits (sorted sets)             │    │
                    │  │  • Active sessions (hashes)              │    │
                    │  │  • Token blacklists (sets)               │    │
                    │  │  • OTP codes (strings with TTL)          │    │
                    │  │  • Login attempts (strings/hashes)       │    │
                    │  └──────────────────────────────────────────┘    │
                    │                                                    │
                    │  ┌──────────────────────────────────────────┐    │
                    │  │  Persistence (Optional AOF/RDB)          │    │
                    │  │  • Critical sessions                      │    │
                    │  │  • Long-lived tokens                      │    │
                    │  └──────────────────────────────────────────┘    │
                    └────────────────────────────────────────────────────┘
```

---

## Current State Analysis

### What's Already Implemented ✅

| Use Case | Status | Data Structure | Key Pattern | Notes |
|----------|--------|----------------|-------------|-------|
| **Rate Limiting** | ✅ Implemented | Sorted Set | `ratelimit:{type}:{key}` | Sliding window algorithm |
| **OTP Storage** | ✅ Implemented | String | `otp:{purpose}:{identifier}` | SHA-256 hashed, TTL |
| **Pending Users** | ✅ Implemented | String (JSON) | `pending_user:{email}` | Signup verification |
| **Refresh Tokens** | ⚠️ Partial | String | `refresh_token:{token_hash}` | Basic storage |
| **TOTP Secrets** | ✅ Implemented | String | `totp_secret:{user_id}` | Temporary during setup |

### Gaps & Improvements Needed ⚠️

1. **No Token Blacklisting** - Cannot revoke JWT access tokens
2. **No Session Tracking** - No active session management in Redis
3. **No Brute Force Protection** - Login attempts tracked in PostgreSQL (slow)
4. **No Device Sessions** - No fast device/session lookup
5. **No Distributed Locks** - No coordination for concurrent operations
6. **No Future-Ready Structures** - Missing OAuth2/WebAuthn state management

---

## Proposed Use Cases

### Priority Classification

| Priority | Use Case | Impact | Complexity | Timeline |
|----------|----------|--------|------------|----------|
| 🔴 **P0** | JWT jti Blacklist | High (Security) | Low | Week 1 |
| 🔴 **P0** | Login Attempt Counters | High (Security) | Low | Week 1 |
| 🟡 **P1** | Session Store (Fast Validation) | High (Performance) | Medium | Week 2 |
| 🟡 **P1** | Refresh Token Blacklist | High (Security) | Low | Week 2 |
| 🟡 **P1** | Device Sessions Tracking | Medium (UX) | Medium | Week 3 |
| 🟢 **P2** | Email Verification Cache | Medium (Performance) | Low | Week 4 |
| 🟢 **P2** | Distributed Locks | Low (Edge Cases) | Medium | Week 5 |
| 🔵 **P3** | PKCE State (OAuth2) | Low (Future) | Low | Q2 2026 |
| 🔵 **P3** | WebAuthn Challenges | Low (Future) | Low | Q2 2026 |

---

## Data Structure Design

### 1. Rate Limiting (✅ Implemented)

**Purpose**: Prevent brute force, abuse, DDoS

**Data Structure**: Sorted Set
**Key Pattern**: `ratelimit:{endpoint}:{key_type}:{key_value}`

**Example**:
```redis
# Key
ratelimit:login:email:user@example.com

# Data (Sorted Set)
ZADD ratelimit:login:email:user@example.com 1704067200000000000 "1704067200000000000"
ZADD ratelimit:login:email:user@example.com 1704067201000000000 "1704067201000000000"
...

# TTL
EXPIRE ratelimit:login:email:user@example.com 960  # window + 60s buffer
```

**Operations**:
```redis
# Remove old entries
ZREMRANGEBYSCORE key 0 (now - window)

# Count current
ZCOUNT key (now - window) +inf

# Add new entry
ZADD key timestamp timestamp

# Check limit
if count < limit: allow
```

**Memory**: ~100 bytes per entry, ~500 bytes per key
**Status**: ✅ **Already Implemented**

---

### 2. Login Attempt Counters (🔴 P0 - New)

**Purpose**: Track failed login attempts per user/IP for account lockout

**Current Issue**: Stored in PostgreSQL → slow, not real-time
**Solution**: Move to Redis for instant checks

#### 2a. Per-Email Attempt Counter

**Data Structure**: String (integer counter) + Hash (metadata)
**Key Pattern**: `login_attempts:email:{email}`

**Example**:
```redis
# Simple counter
SET login_attempts:email:user@example.com 3 EX 1800

# Or with metadata (better)
HSET login_attempts:email:user@example.com count 3
HSET login_attempts:email:user@example.com first_attempt_at 1704067200
HSET login_attempts:email:user@example.com last_attempt_at 1704067500
HSET login_attempts:email:user@example.com locked_until 1704069000
EXPIRE login_attempts:email:user@example.com 1800
```

**Operations**:
```go
// Increment on failed login
HINCRBY login_attempts:email:user@example.com count 1
HSET login_attempts:email:user@example.com last_attempt_at (now)

// Check if locked
locked_until := HGET login_attempts:email:user@example.com locked_until
if locked_until > now: return "account_locked"

// Check if should lock
count := HGET login_attempts:email:user@example.com count
if count >= max_attempts:
    HSET login_attempts:email:user@example.com locked_until (now + lockout_duration)

// Reset on successful login
DEL login_attempts:email:user@example.com
```

#### 2b. Per-IP Attempt Counter

**Key Pattern**: `login_attempts:ip:{ip_address}`

**Same structure as email-based**, tracks attempts from specific IP

**TTL**: 30 minutes (matches lockout duration)
**Memory**: ~200 bytes per key
**Eviction**: Automatic via TTL

**Benefits**:
- ✅ **Real-time** lockout checking (no DB query)
- ✅ **Fast** (<1ms vs 50ms+ DB query)
- ✅ **Scalable** (independent of DB load)
- ✅ **Auto-cleanup** via TTL

---

### 3. JWT jti Blacklist (🔴 P0 - New)

**Purpose**: Emergency revocation of JWT access tokens

**Background**: JWT tokens are stateless, cannot be revoked. Solution: blacklist revoked tokens by their `jti` (JWT ID).

**Data Structure**: Set or Sorted Set
**Key Pattern**: `blacklist:jwt:{jti}` or centralized `blacklist:jwt` set

#### Option A: Individual Keys (Recommended)

```redis
# Each blacklisted token gets a key
SET blacklist:jwt:{jti} "1" EX {remaining_ttl}

# Check if blacklisted
EXISTS blacklist:jwt:{jti}
```

**Pros**:
- Simple, fast EXISTS check
- Automatic cleanup via TTL
- No memory for expired tokens

**Cons**:
- Many keys (one per blacklisted token)

#### Option B: Centralized Set (Alternative)

```redis
# All blacklisted tokens in one sorted set
ZADD blacklist:jwt {exp_timestamp} {jti}

# Check if blacklisted
ZSCORE blacklist:jwt {jti}

# Cleanup expired
ZREMRANGEBYSCORE blacklist:jwt 0 (now)
```

**Pros**:
- Single data structure
- Easy to query all blacklisted tokens

**Cons**:
- Manual cleanup needed
- No automatic TTL per token

**Recommendation**: **Option A** (individual keys with TTL)

**Implementation**:
```go
// Blacklist token
func (r *RedisRepo) BlacklistJWT(ctx context.Context, jti string, expiresAt time.Time) error {
    ttl := time.Until(expiresAt)
    if ttl <= 0 {
        return nil // Already expired
    }

    key := fmt.Sprintf("blacklist:jwt:%s", jti)
    return r.client.Set(ctx, key, "1", ttl).Err()
}

// Check if blacklisted
func (r *RedisRepo) IsJWTBlacklisted(ctx context.Context, jti string) (bool, error) {
    key := fmt.Sprintf("blacklist:jwt:%s", jti)
    exists, err := r.client.Exists(ctx, key).Result()
    return exists > 0, err
}
```

**Use Cases**:
- User logs out → blacklist access token
- Admin revokes user's sessions → blacklist all tokens
- Security breach → mass revocation
- User changes password → blacklist all old tokens

**Memory**: ~100 bytes per blacklisted token
**TTL**: Token's remaining lifetime
**Peak Memory**: If 1000 tokens blacklisted, ~100 KB

---

### 4. Refresh Token Blacklist (🟡 P1 - Enhancement)

**Purpose**: Revoke refresh tokens (logout, security events)

**Current State**: Refresh tokens stored in PostgreSQL only
**Problem**: Slow validation (DB query every refresh)
**Solution**: Cache in Redis for fast validation

**Data Structure**: Set or Hash
**Key Pattern**: `blacklist:refresh_token:{token_hash}`

**Implementation**:
```redis
# Blacklist refresh token
SET blacklist:refresh_token:{token_hash} "1" EX {ttl}

# Or store metadata
HSET blacklist:refresh_token:{token_hash} revoked_at (timestamp)
HSET blacklist:refresh_token:{token_hash} reason "user_logout"
EXPIRE blacklist:refresh_token:{token_hash} {ttl}
```

**Alternative: Centralized Whitelist** (More Memory Efficient)

Instead of blacklisting revoked tokens, **whitelist active tokens**:

```redis
# Store only active refresh tokens
HSET refresh_tokens:active {token_hash} {user_id}
EXPIRE refresh_tokens:active:{token_hash} {ttl}

# On token refresh/logout
DEL refresh_tokens:active:{token_hash}

# Validate
EXISTS refresh_tokens:active:{token_hash}
```

**Comparison**:

| Approach | Memory | Lookup Speed | Cleanup |
|----------|--------|--------------|---------|
| **Blacklist** | Low (only revoked) | Fast (EXISTS) | Automatic (TTL) |
| **Whitelist** | High (all active) | Fast (EXISTS) | Automatic (TTL) |

**Recommendation**: **Hybrid Approach**
- Primary: PostgreSQL (source of truth)
- Cache: Redis (fast validation)
- Blacklist revoked tokens in Redis
- Fallback to PostgreSQL on cache miss

---

### 5. Session Store (🟡 P1 - New)

**Purpose**: Fast session validation without DB queries

**Current State**: Sessions stored only in PostgreSQL
**Problem**: Every authenticated request hits DB (slow, high load)
**Solution**: Cache sessions in Redis

**Data Structure**: Hash
**Key Pattern**: `session:{session_id}` or `session:user:{user_id}:{session_id}`

**Schema**:
```redis
HSET session:{session_id} user_id "uuid"
HSET session:{session_id} email "user@example.com"
HSET session:{session_id} ip_address "192.168.1.1"
HSET session:{session_id} user_agent "Mozilla/5.0..."
HSET session:{session_id} created_at "1704067200"
HSET session:{session_id} last_activity_at "1704067500"
HSET session:{session_id} device_fingerprint "abc123"
HSET session:{session_id} expires_at "1704153600"

EXPIRE session:{session_id} 86400  # 24 hours
```

**Operations**:
```go
// Create session
HSET session:{id} field value
EXPIRE session:{id} {ttl}

// Validate session
session := HGETALL session:{id}
if session.expires_at < now: return "expired"

// Update activity
HSET session:{id} last_activity_at (now)

// Revoke session
DEL session:{id}

// Get user's sessions
SCAN 0 MATCH session:user:{user_id}:*
```

**Session Hierarchy**:
```
User (UUID)
  ├─ Session 1 (Desktop - Chrome)
  ├─ Session 2 (Mobile - Safari)
  └─ Session 3 (Tablet - Firefox)
```

**Memory**: ~500 bytes per session
**10M active sessions**: ~5 GB

**TTL Strategy**:
- **Short-lived**: 1 hour (mobile apps)
- **Standard**: 24 hours (web browsers)
- **Long-lived**: 7 days (remember me)

**Refresh Strategy**:
```go
// On each authenticated request
EXPIRE session:{id} {ttl}  // Sliding window
HSET session:{id} last_activity_at (now)
```

---

### 6. Device Sessions Tracking (🟡 P1 - New)

**Purpose**: Track all active sessions per user, enable "view devices" and "logout everywhere"

**Data Structure**: Sorted Set (by last activity) + Individual session hashes
**Key Pattern**: `user:{user_id}:sessions` + `session:{session_id}`

**Schema**:
```redis
# User's session index (sorted by last activity)
ZADD user:{user_id}:sessions {last_activity_timestamp} {session_id}

# Individual session data
HSET session:{session_id} user_id {user_id}
HSET session:{session_id} device_name "iPhone 14 Pro"
HSET session:{session_id} device_type "mobile"
HSET session:{session_id} browser "Safari 17"
HSET session:{session_id} os "iOS 17.2"
HSET session:{session_id} ip_address "192.168.1.1"
HSET session:{session_id} location "New York, USA"
HSET session:{session_id} created_at "1704067200"
HSET session:{session_id} last_activity_at "1704067500"
```

**Operations**:
```go
// Add session
ZADD user:{user_id}:sessions (now) {session_id}
HSET session:{session_id} ...fields...

// Update activity
ZADD user:{user_id}:sessions (now) {session_id}
HSET session:{session_id} last_activity_at (now)

// List user's sessions (sorted by activity)
session_ids := ZREVRANGE user:{user_id}:sessions 0 -1
for each session_id:
    session := HGETALL session:{session_id}

// Logout everywhere
session_ids := ZRANGE user:{user_id}:sessions 0 -1
for each session_id:
    DEL session:{session_id}
DEL user:{user_id}:sessions

// Logout specific device
ZREM user:{user_id}:sessions {session_id}
DEL session:{session_id}

// Cleanup inactive sessions (background job)
inactive_sessions := ZRANGEBYSCORE user:{user_id}:sessions 0 (now - 30days)
for each session_id:
    ZREM user:{user_id}:sessions {session_id}
    DEL session:{session_id}
```

**API Endpoint Design**:
```go
GET /api/v1/auth/sessions
Response:
{
  "sessions": [
    {
      "session_id": "uuid",
      "device_name": "iPhone 14 Pro",
      "device_type": "mobile",
      "browser": "Safari 17",
      "os": "iOS 17.2",
      "ip_address": "192.168.1.1",
      "location": "New York, USA",
      "created_at": "2025-01-15T10:30:00Z",
      "last_activity_at": "2025-01-15T12:45:00Z",
      "is_current": true
    },
    ...
  ]
}

DELETE /api/v1/auth/sessions/{session_id}  # Logout specific session
DELETE /api/v1/auth/sessions               # Logout all sessions
```

**Memory**: ~1 KB per session
**1M users × 3 sessions avg**: ~3 GB

---

### 7. OTP Storage (✅ Implemented - Review)

**Current Implementation**: Good, but can be enhanced

**Data Structure**: String (hashed OTP)
**Key Pattern**: `otp:{purpose}:{identifier}`

**Current**:
```redis
SET otp:signup:user@example.com {hashed_otp} EX 300
```

**Enhancement**: Add metadata for security

```redis
# Store as hash
HSET otp:signup:user@example.com code {hashed_otp}
HSET otp:signup:user@example.com attempts 0
HSET otp:signup:user@example.com created_at (timestamp)
HSET otp:signup:user@example.com ip_address "192.168.1.1"
EXPIRE otp:signup:user@example.com 300

# Track verification attempts
HINCRBY otp:signup:user@example.com attempts 1
attempts := HGET otp:signup:user@example.com attempts
if attempts > 3: return "too_many_attempts"
```

**Benefits**:
- ✅ Prevent brute force OTP guessing
- ✅ Track suspicious activity
- ✅ Audit trail (IP, attempts)

---

### 8. Email Verification Token Cache (🟢 P2 - New)

**Purpose**: Cache email verification tokens for fast validation

**Current State**: Tokens stored only in PostgreSQL
**Problem**: Every email verification hits DB
**Solution**: Cache in Redis

**Data Structure**: String or Hash
**Key Pattern**: `email_verification:{token_hash}`

**Implementation**:
```redis
# Simple
SET email_verification:{token_hash} {user_id} EX 3600

# With metadata
HSET email_verification:{token_hash} user_id {user_id}
HSET email_verification:{token_hash} email "user@example.com"
HSET email_verification:{token_hash} created_at (timestamp)
HSET email_verification:{token_hash} used false
EXPIRE email_verification:{token_hash} 3600
```

**Operations**:
```go
// Store token
SET email_verification:{token} {user_id} EX 3600

// Validate token
user_id := GET email_verification:{token}
if user_id == nil: fallback to PostgreSQL

// Mark as used (prevent replay)
HSET email_verification:{token} used true
DEL email_verification:{token}  // or let it expire
```

**TTL**: 1 hour (email verification tokens)
**Memory**: ~100 bytes per token
**Peak**: 10K pending verifications = ~1 MB

---

### 9. Distributed Locks (🟢 P2 - New)

**Purpose**: Prevent race conditions in distributed system

**Use Cases**:
- Prevent duplicate user creation (same email, concurrent requests)
- Prevent double-spending refresh tokens
- Prevent concurrent password changes
- Prevent concurrent 2FA setup

**Data Structure**: String with SETNX (Set if Not Exists)
**Key Pattern**: `lock:{resource}:{identifier}`

**Implementation** (Redlock Algorithm):

```go
// Acquire lock
func AcquireLock(ctx context.Context, resource string, ttl time.Duration) (string, error) {
    lockKey := fmt.Sprintf("lock:%s", resource)
    lockValue := uuid.New().String()  // Unique lock ID

    // Try to set if not exists
    success, err := redis.SetNX(ctx, lockKey, lockValue, ttl).Result()
    if err != nil {
        return "", err
    }

    if !success {
        return "", ErrLockNotAcquired
    }

    return lockValue, nil
}

// Release lock (safely)
func ReleaseLock(ctx context.Context, resource string, lockValue string) error {
    lockKey := fmt.Sprintf("lock:%s", resource)

    // Lua script for atomic check-and-delete
    script := `
        if redis.call("GET", KEYS[1]) == ARGV[1] then
            return redis.call("DEL", KEYS[1])
        else
            return 0
        end
    `

    return redis.Eval(ctx, script, []string{lockKey}, lockValue).Err()
}

// Usage
lockID, err := AcquireLock(ctx, "user:create:user@example.com", 5*time.Second)
if err != nil {
    return ErrResourceLocked
}
defer ReleaseLock(ctx, "user:create:user@example.com", lockID)

// Critical section
createUser(...)
```

**Alternative**: Use `github.com/bsm/redislock` library

**TTL**: 5-10 seconds (short-lived)
**Auto-release**: Prevents deadlocks if service crashes

**Important**: For high-availability, use **Redlock algorithm** with multiple Redis instances.

---

### 10. PKCE State Storage (🔵 P3 - Future, OAuth2)

**Purpose**: Store PKCE code verifier during OAuth2 authorization code flow

**Background**: OAuth2 with PKCE requires storing state between authorization and token exchange.

**Data Structure**: Hash
**Key Pattern**: `oauth2:pkce:{state}`

**Schema**:
```redis
HSET oauth2:pkce:{state} code_verifier {verifier}
HSET oauth2:pkce:{state} code_challenge {challenge}
HSET oauth2:pkce:{state} code_challenge_method "S256"
HSET oauth2:pkce:{state} client_id {client_id}
HSET oauth2:pkce:{state} redirect_uri {uri}
HSET oauth2:pkce:{state} scope "openid profile email"
HSET oauth2:pkce:{state} nonce {nonce}
HSET oauth2:pkce:{state} created_at (timestamp)
EXPIRE oauth2:pkce:{state} 600  # 10 minutes
```

**Flow**:
```
1. Client initiates OAuth2 flow
   → Store PKCE state in Redis

2. User authorizes
   → Generate authorization code
   → Link code to state

3. Client exchanges code for token
   → Validate PKCE verifier from Redis
   → Delete state

4. If not exchanged within 10 min
   → Redis auto-expires (prevents stale state)
```

**TTL**: 10 minutes
**Memory**: ~500 bytes per state

---

### 11. WebAuthn Challenge Storage (🔵 P3 - Future)

**Purpose**: Store WebAuthn challenges for registration/authentication

**Data Structure**: Hash
**Key Pattern**: `webauthn:challenge:{challenge_id}`

**Schema**:
```redis
HSET webauthn:challenge:{id} challenge {base64_challenge}
HSET webauthn:challenge:{id} user_id {user_id}
HSET webauthn:challenge:{id} operation "registration" # or "authentication"
HSET webauthn:challenge:{id} created_at (timestamp)
HSET webauthn:challenge:{id} ip_address "192.168.1.1"
EXPIRE webauthn:challenge:{id} 300  # 5 minutes
```

**Flow**:
```
1. User initiates WebAuthn registration
   → Generate challenge
   → Store in Redis

2. Client signs challenge with authenticator
   → Submit signature

3. Server validates signature
   → Retrieve challenge from Redis
   → Verify signature
   → Delete challenge (one-time use)
```

**TTL**: 5 minutes
**Memory**: ~300 bytes per challenge

---

## Key Naming Convention

### Standard Format

```
{namespace}:{entity}:{identifier}[:{sub_identifier}]
```

### Namespaces

| Namespace | Purpose | Examples |
|-----------|---------|----------|
| `ratelimit` | Rate limiting | `ratelimit:login:email:user@example.com` |
| `otp` | OTP codes | `otp:signup:user@example.com` |
| `session` | User sessions | `session:{session_id}` |
| `user` | User-related data | `user:{user_id}:sessions` |
| `blacklist` | Token blacklists | `blacklist:jwt:{jti}` |
| `lock` | Distributed locks | `lock:user:create:{email}` |
| `login_attempts` | Login tracking | `login_attempts:email:{email}` |
| `email_verification` | Email tokens | `email_verification:{token_hash}` |
| `oauth2` | OAuth2 state | `oauth2:pkce:{state}` |
| `webauthn` | WebAuthn challenges | `webauthn:challenge:{id}` |
| `pending_user` | Pending signups | `pending_user:{email}` |
| `totp_secret` | 2FA setup | `totp_secret:{user_id}` |

### Key Components

1. **Namespace**: Logical grouping (e.g., `session`, `otp`)
2. **Entity**: What the data represents (e.g., `user`, `token`)
3. **Identifier**: Unique ID (e.g., `user_id`, `email`, `jti`)
4. **Sub-identifier**: Optional nested ID (e.g., `session_id` under user)

### Examples

```redis
# Good ✅
ratelimit:login:email:user@example.com
session:550e8400-e29b-41d4-a716-446655440000
user:123e4567-e89b-12d3-a456-426614174000:sessions
blacklist:jwt:9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d

# Bad ❌
login_ratelimit_user@example.com  # No clear structure
session_123                        # Ambiguous
user_sessions_456                  # Hard to parse
```

### Delimiter Rules

- Use `:` for hierarchical separation
- Use `-` within identifiers (e.g., UUIDs)
- Use `_` within names (e.g., `login_attempts`)
- Avoid spaces, special characters

### Pattern Matching

Design keys for efficient `SCAN` operations:

```redis
# Get all sessions for a user
SCAN 0 MATCH user:{user_id}:sessions:*

# Get all rate limit keys for login
SCAN 0 MATCH ratelimit:login:*

# Get all blacklisted JWTs
SCAN 0 MATCH blacklist:jwt:*
```

---

## TTL & Eviction Strategy

### TTL Policy by Use Case

| Use Case | TTL | Rationale | Eviction |
|----------|-----|-----------|----------|
| **Rate Limit** | Window + 60s | Sliding window needs buffer | Auto (TTL) |
| **OTP** | 5 minutes | Security best practice | Auto (TTL) |
| **Session** | 24 hours | Standard session lifetime | Auto (TTL + LRU) |
| **JWT Blacklist** | Token lifetime | No longer needed after expiry | Auto (TTL) |
| **Refresh Token Blacklist** | Token lifetime | Revoked tokens expire naturally | Auto (TTL) |
| **Login Attempts** | 30 minutes | Reset after lockout period | Auto (TTL) |
| **Email Verification** | 1 hour | Long enough for email delivery | Auto (TTL) |
| **Distributed Lock** | 10 seconds | Prevent deadlocks | Auto (TTL) |
| **PKCE State** | 10 minutes | OAuth2 spec recommendation | Auto (TTL) |
| **WebAuthn Challenge** | 5 minutes | Fast user interaction expected | Auto (TTL) |

### Eviction Policies

**Redis Configuration** (`redis.conf`):

```conf
# Maximum memory
maxmemory 2gb

# Eviction policy: Least Recently Used (LRU) for keys with TTL
maxmemory-policy volatile-lru

# Sample size for LRU algorithm (higher = more accurate)
maxmemory-samples 5
```

**Eviction Policy Options**:

| Policy | Description | Use Case |
|--------|-------------|----------|
| `volatile-lru` | ✅ **Recommended** | Evict least recently used keys **with TTL** |
| `allkeys-lru` | Evict any key (LRU) | If all keys can be evicted |
| `volatile-ttl` | Evict keys with shortest TTL | If TTL priority matters |
| `noeviction` | Return errors when full | Never evict (not recommended) |

**Our Choice**: `volatile-lru`
- ✅ Only evicts keys with TTL (safe)
- ✅ Keeps frequently accessed data
- ✅ Auto-cleans inactive data

### TTL Refresh Strategy

**Sliding Window** (for sessions):

```go
// On every authenticated request
redis.Expire(ctx, sessionKey, 24*time.Hour)
```

**Fixed Window** (for OTP, tokens):

```go
// Set once, never refresh
redis.SetEx(ctx, otpKey, otp, 5*time.Minute)
```

### Background Cleanup Jobs

Some keys may need manual cleanup:

```go
// Cleanup expired sessions (belt-and-suspenders)
func CleanupExpiredSessions(ctx context.Context) {
    cursor := uint64(0)
    for {
        keys, cursor, err := redis.Scan(ctx, cursor, "session:*", 100).Result()
        for _, key := range keys {
            session := redis.HGetAll(ctx, key).Val()
            expiresAt := session["expires_at"]
            if expiresAt < now() {
                redis.Del(ctx, key)
            }
        }
        if cursor == 0 {
            break
        }
    }
}
```

Run as cron job: Every 1 hour

---

## Memory Management

### Memory Estimation

| Use Case | Data Size | Volume | Total Memory |
|----------|-----------|--------|--------------|
| Rate Limits | 500 bytes/key | 10K keys | ~5 MB |
| Sessions | 1 KB/session | 1M sessions | ~1 GB |
| Device Sessions | 1 KB/session | 3M sessions (3/user) | ~3 GB |
| JWT Blacklist | 100 bytes/token | 10K tokens | ~1 MB |
| Login Attempts | 200 bytes/key | 100K keys | ~20 MB |
| OTP | 200 bytes/key | 50K keys | ~10 MB |
| Locks | 100 bytes/lock | 1K locks | ~100 KB |
| **Total Estimated** | | | **~4.2 GB** |

**Recommendation**: Provision **8 GB Redis instance** for headroom.

### Memory Optimization Tips

1. **Use Hashes for Related Data**
   ```redis
   # Bad: 3 keys
   SET session:123:user_id "uuid"
   SET session:123:email "user@example.com"
   SET session:123:created_at "1704067200"

   # Good: 1 hash
   HSET session:123 user_id "uuid" email "user@example.com" created_at "1704067200"
   ```

2. **Compress Large Values**
   ```go
   // Compress JSON before storing
   compressed := gzip.Compress(json)
   redis.Set(ctx, key, compressed, ttl)
   ```

3. **Use Shorter Keys**
   ```redis
   # Bad (verbose)
   authentication:service:session:user:123e4567-e89b-12d3-a456-426614174000

   # Good (concise)
   sess:123e4567-e89b-12d3-a456-426614174000
   ```

4. **Set Aggressive TTLs**
   - Every key should have a TTL
   - No key should live forever
   - Check: `redis-cli KEYS * | xargs redis-cli TTL` → should not return `-1`

5. **Monitor Memory Usage**
   ```bash
   redis-cli INFO memory
   redis-cli --bigkeys  # Find largest keys
   redis-cli --memkeys  # Memory usage per key
   ```

### Memory Alerts

Set up alerts for:
- Memory usage > 80%
- Evictions > 100/sec
- Keys without TTL > 1000

---

## High Availability & Scaling

### Deployment Options

#### Option 1: Single Redis Instance (Development) ⚠️

```yaml
# docker-compose.yml
redis:
  image: redis:7-alpine
  ports:
    - "6379:6379"
  command: redis-server --maxmemory 2gb --maxmemory-policy volatile-lru
```

**Pros**: Simple
**Cons**: Single point of failure

---

#### Option 2: Redis Sentinel (Recommended for Production) ✅

**Architecture**:
```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  Sentinel 1 │◄────►│  Sentinel 2 │◄────►│  Sentinel 3 │
└──────┬──────┘      └──────┬──────┘      └──────┬──────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                            │
              ┌─────────────▼─────────────┐
              │     Redis Master          │
              │  (Read/Write)             │
              └─────────────┬─────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
    ┌─────────▼─────────┐      ┌─────────▼─────────┐
    │  Redis Replica 1  │      │  Redis Replica 2  │
    │  (Read-only)      │      │  (Read-only)      │
    └───────────────────┘      └───────────────────┘
```

**Features**:
- ✅ Automatic failover (if master dies, promote replica)
- ✅ High availability (99.9%+ uptime)
- ✅ Read scaling (read from replicas)

**Configuration**:
```yaml
# docker-compose.yml
redis-master:
  image: redis:7-alpine
  command: redis-server --maxmemory 4gb

redis-replica-1:
  image: redis:7-alpine
  command: redis-server --replicaof redis-master 6379

redis-replica-2:
  image: redis:7-alpine
  command: redis-server --replicaof redis-master 6379

redis-sentinel-1:
  image: redis:7-alpine
  command: redis-sentinel /etc/redis/sentinel.conf

redis-sentinel-2:
  image: redis:7-alpine
  command: redis-sentinel /etc/redis/sentinel.conf

redis-sentinel-3:
  image: redis:7-alpine
  command: redis-sentinel /etc/redis/sentinel.conf
```

**Go Client Configuration**:
```go
import "github.com/redis/go-redis/v9"

client := redis.NewFailoverClient(&redis.FailoverOptions{
    MasterName:    "mymaster",
    SentinelAddrs: []string{"sentinel1:26379", "sentinel2:26379", "sentinel3:26379"},
    DB:            0,
    PoolSize:      50,
})
```

---

#### Option 3: Redis Cluster (High Scale) ⚙️

For **10M+ active users**:

**Architecture**:
```
┌──────────┐  ┌──────────┐  ┌──────────┐
│ Master 1 │  │ Master 2 │  │ Master 3 │
│  (0-5461)│  │(5462-10922)│ │(10923-16383)│
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │            │            │
┌────▼─────┐  ┌───▼──────┐  ┌───▼──────┐
│Replica 1 │  │Replica 2 │  │Replica 3 │
└──────────┘  └──────────┘  └──────────┘
```

**Features**:
- ✅ Horizontal scaling (sharding)
- ✅ Handle billions of keys
- ✅ Distributed across nodes

**Go Client**:
```go
client := redis.NewClusterClient(&redis.ClusterOptions{
    Addrs: []string{"node1:6379", "node2:6379", "node3:6379"},
})
```

---

#### Option 4: Managed Redis (AWS ElastiCache, GCP Memorystore) ☁️

**Pros**:
- ✅ Fully managed (no ops)
- ✅ Automatic backups
- ✅ Automatic failover
- ✅ Monitoring included

**Cons**:
- 💰 More expensive
- 🔒 Vendor lock-in

**Recommendation**: Use for production

---

### Scaling Strategy

| Stage | Users | Sessions | Redis Setup | Memory |
|-------|-------|----------|-------------|--------|
| **MVP** | 0-10K | 10K | Single instance | 2 GB |
| **Growth** | 10K-100K | 100K | Sentinel (1M+2R) | 4 GB |
| **Scale** | 100K-1M | 1M | Sentinel (1M+2R) | 8 GB |
| **Enterprise** | 1M-10M | 10M | Cluster (3M+3R) | 32 GB |

---

## Security Considerations

### 1. Data Encryption

**At Rest** (Optional for sensitive data):
```bash
# Enable RDB/AOF encryption (Redis 6+)
redis-server --enable-protected-configs yes \
             --aclfile /etc/redis/users.acl
```

**In Transit** (TLS):
```bash
redis-server --tls-port 6380 \
             --tls-cert-file /path/to/cert.pem \
             --tls-key-file /path/to/key.pem \
             --tls-ca-cert-file /path/to/ca.pem
```

**Go Client with TLS**:
```go
client := redis.NewClient(&redis.Options{
    Addr: "localhost:6380",
    TLSConfig: &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
    },
})
```

### 2. Access Control (Redis ACL)

**Create dedicated user** (Redis 6+):
```redis
# Admin user (full access)
ACL SETUSER admin on >strong_password ~* +@all

# Application user (limited access)
ACL SETUSER authservice on >app_password \
    ~ratelimit:* ~session:* ~otp:* ~user:* ~blacklist:* ~lock:* \
    +@read +@write +@hash +@string +@sortedset -@dangerous
```

**Go Client**:
```go
client := redis.NewClient(&redis.Options{
    Addr:     "localhost:6379",
    Username: "authservice",
    Password: "app_password",
})
```

### 3. Network Security

**Bind to Localhost** (if single-server):
```bash
redis-server --bind 127.0.0.1
```

**Private Network** (if distributed):
```bash
redis-server --bind 10.0.1.10 --protected-mode yes
```

**Firewall Rules**:
```bash
# Allow only app servers
iptables -A INPUT -p tcp --dport 6379 -s 10.0.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 6379 -j DROP
```

### 4. Sensitive Data Hashing

**Never store plaintext**:
```go
// Bad ❌
redis.Set(ctx, "otp:signup:user@example.com", "123456", 5*time.Minute)

// Good ✅
hashedOTP := sha256.Sum256([]byte("123456"))
redis.Set(ctx, "otp:signup:user@example.com", hex.EncodeToString(hashedOTP[:]), 5*time.Minute)
```

**Hash sensitive identifiers**:
```go
// JWT tokens, refresh tokens
tokenHash := sha256.Sum256([]byte(token))
redis.Set(ctx, fmt.Sprintf("blacklist:jwt:%x", tokenHash), "1", ttl)
```

### 5. Rate Limiting Redis Access

Prevent Redis abuse from compromised app:
```redis
# Limit client connections
maxclients 10000

# Limit command execution time
slowlog-log-slower-than 10000  # 10ms
slowlog-max-len 128

# Disable dangerous commands
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG ""
rename-command SHUTDOWN ""
```

---

## Monitoring & Observability

### Key Metrics to Track

| Metric | Command | Alert Threshold |
|--------|---------|-----------------|
| **Memory Usage** | `INFO memory` | > 80% |
| **Connected Clients** | `INFO clients` | > 1000 |
| **Commands/sec** | `INFO stats` | Baseline +50% |
| **Keyspace Hits** | `INFO stats` | < 90% hit rate |
| **Evictions** | `INFO stats` | > 100/sec |
| **Slow Commands** | `SLOWLOG GET` | > 10ms |
| **Replication Lag** | `INFO replication` | > 1 second |
| **Rejected Connections** | `INFO stats` | > 0 |

### Redis INFO Commands

```bash
# Memory
redis-cli INFO memory | grep -E "used_memory|maxmemory"

# Stats
redis-cli INFO stats | grep -E "instantaneous_ops_per_sec|keyspace"

# Replication (if using Sentinel/Cluster)
redis-cli INFO replication
```

### Application-Level Metrics (Prometheus)

```go
// internal/metrics/redis_metrics.go

var (
    RedisOperations = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "redis_operations_total",
            Help: "Total Redis operations",
        },
        []string{"operation", "status"},
    )

    RedisLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "redis_operation_duration_seconds",
            Help:    "Redis operation latency",
            Buckets: prometheus.DefBuckets,
        },
        []string{"operation"},
    )

    RedisCacheHits = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "redis_cache_hits_total",
            Help: "Redis cache hits vs misses",
        },
        []string{"cache_type", "result"}, // result: hit, miss
    )
)
```

### Grafana Dashboard

**Key Panels**:
1. Memory Usage (% and absolute)
2. Operations per second
3. Cache hit rate (%)
4. Average latency (ms)
5. Evictions per second
6. Connected clients
7. Keyspace size (total keys)
8. Slow commands (log)

### Alerting Rules

```yaml
# Prometheus alerts
groups:
  - name: redis
    rules:
      - alert: RedisMemoryHigh
        expr: redis_memory_used_bytes / redis_memory_max_bytes > 0.8
        for: 5m
        annotations:
          summary: "Redis memory usage above 80%"

      - alert: RedisHighEvictionRate
        expr: rate(redis_evicted_keys_total[5m]) > 100
        for: 5m
        annotations:
          summary: "High eviction rate (>100/sec)"

      - alert: RedisLowHitRate
        expr: redis_keyspace_hits_total / (redis_keyspace_hits_total + redis_keyspace_misses_total) < 0.9
        for: 10m
        annotations:
          summary: "Cache hit rate below 90%"

      - alert: RedisHighLatency
        expr: redis_operation_duration_seconds{quantile="0.95"} > 0.01
        for: 5m
        annotations:
          summary: "P95 latency > 10ms"
```

---

## Migration Strategy

### Phase 1: Foundation (Week 1)

**Priority**: P0 use cases

1. ✅ **JWT jti Blacklist**
   - Add blacklist check to JWT validation middleware
   - Create blacklist methods in Redis repository
   - Test with token revocation

2. ✅ **Login Attempt Counters**
   - Move from PostgreSQL to Redis
   - Update login handler
   - Test account lockout flow

**Migration Steps**:
```go
// 1. Add Redis methods
func (r *RedisRepo) IncrementLoginAttempts(ctx context.Context, email string) (int, error)
func (r *RedisRepo) GetLoginAttempts(ctx context.Context, email string) (int, error)
func (r *RedisRepo) ResetLoginAttempts(ctx context.Context, email string) error
func (r *RedisRepo) IsAccountLocked(ctx context.Context, email string) (bool, time.Time, error)
func (r *RedisRepo) LockAccount(ctx context.Context, email string, duration time.Duration) error

// 2. Update login handler
attempts, _ := redisRepo.IncrementLoginAttempts(ctx, email)
if attempts > maxAttempts {
    redisRepo.LockAccount(ctx, email, lockoutDuration)
    return "account_locked"
}

// 3. On successful login
redisRepo.ResetLoginAttempts(ctx, email)
```

**Testing**:
```bash
# Test account lockout
for i in {1..10}; do
  curl -X POST /api/v1/auth/login \
    -d '{"email":"test@example.com","password":"wrong"}'
done

# Verify Redis
redis-cli HGET login_attempts:email:test@example.com count
redis-cli HGET login_attempts:email:test@example.com locked_until
```

---

### Phase 2: Performance (Week 2)

**Priority**: P1 use cases

3. ✅ **Session Store**
   - Create session management in Redis
   - Update JWT middleware to check Redis first
   - Fallback to PostgreSQL on cache miss

4. ✅ **Refresh Token Blacklist**
   - Add blacklist check to refresh endpoint
   - Invalidate on logout

**Migration Steps**:
```go
// 1. Create session on login
session := &Session{
    ID:       uuid.New(),
    UserID:   user.ID,
    // ... fields
}
redisRepo.CreateSession(ctx, session)
postgresRepo.CreateSession(ctx, session)  // Keep PostgreSQL as source of truth

// 2. Validate session (middleware)
session, err := redisRepo.GetSession(ctx, sessionID)
if err != nil {
    // Cache miss, fallback to PostgreSQL
    session, err = postgresRepo.GetSession(ctx, sessionID)
    if err == nil {
        // Warm cache
        redisRepo.CreateSession(ctx, session)
    }
}

// 3. Invalidate session (logout)
redisRepo.DeleteSession(ctx, sessionID)
postgresRepo.InvalidateSession(ctx, sessionID)
```

---

### Phase 3: Enhanced Features (Week 3)

5. ✅ **Device Sessions Tracking**
   - API endpoints for listing sessions
   - Logout specific device
   - Logout all devices

**New Endpoints**:
```go
GET    /api/v1/auth/sessions        # List user's sessions
DELETE /api/v1/auth/sessions/:id    # Logout specific session
DELETE /api/v1/auth/sessions        # Logout all sessions
```

---

### Phase 4: Optimization (Week 4-5)

6. ✅ **Email Verification Cache**
7. ✅ **Distributed Locks**

---

### Phase 5: Future Features (Q2 2026)

8. 🔵 **PKCE State** (when implementing OAuth2)
9. 🔵 **WebAuthn Challenges** (when implementing WebAuthn)

---

## Implementation Roadmap

### Week 1: Critical Security (P0)

**Tasks**:
- [x] Design Redis architecture (this document)
- [ ] Implement JWT jti blacklist
  - [ ] Add `BlacklistJWT()` method
  - [ ] Add `IsJWTBlacklisted()` method
  - [ ] Update JWT validation middleware
  - [ ] Add logout endpoint to blacklist token
  - [ ] Test revocation flow
- [ ] Implement login attempt counters
  - [ ] Add `IncrementLoginAttempts()` method
  - [ ] Add `IsAccountLocked()` method
  - [ ] Add `LockAccount()` method
  - [ ] Update login handler
  - [ ] Test lockout flow
- [ ] Write unit tests
- [ ] Update documentation

**Deliverables**:
- ✅ JWT tokens can be revoked
- ✅ Brute force protection working
- ✅ Tests passing

---

### Week 2: Performance (P1)

**Tasks**:
- [ ] Implement session store
  - [ ] Add `CreateSession()` method
  - [ ] Add `GetSession()` method
  - [ ] Add `UpdateSession()` method
  - [ ] Add `DeleteSession()` method
  - [ ] Update authentication middleware
  - [ ] Add cache warming logic
- [ ] Implement refresh token blacklist
  - [ ] Add `BlacklistRefreshToken()` method
  - [ ] Update refresh endpoint
  - [ ] Update logout endpoint
- [ ] Performance testing
  - [ ] Benchmark session validation
  - [ ] Measure cache hit rate
- [ ] Write unit tests

**Deliverables**:
- ✅ Session validation <5ms (vs 50ms+ DB)
- ✅ Cache hit rate >90%
- ✅ Refresh tokens revocable

---

### Week 3: Enhanced Features (P1)

**Tasks**:
- [ ] Implement device sessions tracking
  - [ ] Add `AddDeviceSession()` method
  - [ ] Add `GetUserSessions()` method
  - [ ] Add `DeleteDeviceSession()` method
  - [ ] Add `DeleteAllUserSessions()` method
- [ ] Create new API endpoints
  - [ ] `GET /api/v1/auth/sessions`
  - [ ] `DELETE /api/v1/auth/sessions/:id`
  - [ ] `DELETE /api/v1/auth/sessions`
- [ ] Add device fingerprinting
- [ ] Write unit tests

**Deliverables**:
- ✅ Users can view active sessions
- ✅ Users can logout specific devices
- ✅ "Logout everywhere" working

---

### Week 4: Optimization (P2)

**Tasks**:
- [ ] Implement email verification cache
- [ ] Implement distributed locks
- [ ] Add Redis monitoring (Prometheus)
- [ ] Optimize memory usage
- [ ] Setup Redis Sentinel (staging)
- [ ] Write comprehensive tests

**Deliverables**:
- ✅ Email verification cached
- ✅ Race conditions prevented
- ✅ Monitoring dashboard live
- ✅ High availability tested

---

### Week 5: Production Readiness

**Tasks**:
- [ ] Load testing (10K+ concurrent users)
- [ ] Security audit
- [ ] Documentation review
- [ ] Runbook creation
- [ ] Production deployment plan
- [ ] Rollback procedures

**Deliverables**:
- ✅ Performance benchmarks met
- ✅ Security review passed
- ✅ Production-ready

---

## Future Enhancements

### Q2 2026

1. **OAuth2/OIDC Provider**
   - Implement PKCE state storage
   - Authorization code caching
   - Token introspection caching

2. **WebAuthn/Passkeys**
   - Challenge storage
   - Credential caching
   - Fast credential lookup

3. **Advanced Security**
   - IP reputation scoring (Redis sorted set)
   - Anomaly detection scores
   - Risk-based authentication caching

4. **Performance**
   - Read-through cache pattern
   - Write-behind cache pattern
   - Predictive cache warming

5. **Multi-Tenancy**
   - Tenant-isolated Redis namespaces
   - Per-tenant rate limits
   - Tenant-aware caching

---

## Appendix A: Redis Commands Reference

### Strings

```redis
SET key value EX seconds       # Set with expiration
GET key                        # Get value
SETEX key seconds value        # Set with expiration (atomic)
SETNX key value                # Set if not exists
DEL key                        # Delete key
EXISTS key                     # Check existence
TTL key                        # Get remaining TTL
EXPIRE key seconds             # Set expiration
```

### Hashes

```redis
HSET key field value           # Set field
HGET key field                 # Get field
HMSET key f1 v1 f2 v2         # Set multiple fields
HGETALL key                    # Get all fields
HDEL key field                 # Delete field
HINCRBY key field increment    # Increment field
HEXISTS key field              # Check field exists
```

### Sorted Sets

```redis
ZADD key score member          # Add member with score
ZRANGE key start stop          # Get range by index
ZRANGEBYSCORE key min max      # Get range by score
ZCOUNT key min max             # Count in range
ZREM key member                # Remove member
ZREMRANGEBYSCORE key min max   # Remove range by score
ZSCORE key member              # Get member's score
```

### Sets

```redis
SADD key member                # Add member
SISMEMBER key member           # Check membership
SMEMBERS key                   # Get all members
SREM key member                # Remove member
SCARD key                      # Get set size
```

---

## Appendix B: Go Redis Client Examples

### Basic Operations

```go
import (
    "context"
    "time"
    "github.com/redis/go-redis/v9"
)

// Initialize client
client := redis.NewClient(&redis.Options{
    Addr:     "localhost:6379",
    Password: "",
    DB:       0,
})

// String operations
ctx := context.Background()
err := client.Set(ctx, "key", "value", 5*time.Minute).Err()
val, err := client.Get(ctx, "key").Result()

// Hash operations
err = client.HSet(ctx, "user:123", "name", "John", "email", "john@example.com").Err()
user, err := client.HGetAll(ctx, "user:123").Result()

// Sorted set operations
err = client.ZAdd(ctx, "leaderboard", redis.Z{Score: 100, Member: "player1"}).Err()
scores, err := client.ZRevRangeWithScores(ctx, "leaderboard", 0, 9).Result()

// Pipeline (batch operations)
pipe := client.Pipeline()
pipe.Set(ctx, "key1", "value1", 0)
pipe.Set(ctx, "key2", "value2", 0)
_, err = pipe.Exec(ctx)

// Transaction (atomic)
err = client.Watch(ctx, func(tx *redis.Tx) error {
    val, err := tx.Get(ctx, "key").Int()
    if err != nil && err != redis.Nil {
        return err
    }

    _, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
        pipe.Set(ctx, "key", val+1, 0)
        return nil
    })
    return err
}, "key")
```

---

## Conclusion

This Redis architecture provides a **comprehensive, future-proof strategy** for the auth service:

### Key Benefits

1. ✅ **Performance**: 50-100x faster than DB for hot operations
2. ✅ **Scalability**: Handles millions of active sessions
3. ✅ **Security**: Token revocation, brute force protection
4. ✅ **Reliability**: TTL-based cleanup, high availability
5. ✅ **Flexibility**: Ready for OAuth2, WebAuthn, multi-tenancy

### Success Metrics

| Metric | Target | Current | Improvement |
|--------|--------|---------|-------------|
| Session validation latency | <5ms | 50ms+ | **10x faster** |
| Login attempt check | <1ms | 20ms+ | **20x faster** |
| Token revocation | Instant | N/A | **New capability** |
| Cache hit rate | >90% | 0% | **New capability** |
| Memory efficiency | <8GB | N/A | **Optimized** |

### Next Steps

1. ✅ **Review & approve** this design document
2. 🔄 **Begin implementation** (Week 1: P0 features)
3. 🔄 **Iterative rollout** (phased approach)
4. 🔄 **Monitor & optimize** (continuous improvement)

---

**Document Status**: 📋 **Ready for Implementation**
**Estimated Effort**: 4-5 weeks for full implementation
**Expected Impact**: High (Security + Performance)

**Prepared by**: Solution Architecture Team
**Review Status**: Pending stakeholder approval
**Last Updated**: 2026-05-24

---

*End of Document*
