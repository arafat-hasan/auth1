# Architecture — Auth Service

Platform-agnostic JWT authentication microservice. Designed to be embedded in any product (Duitara, SaaS, e-commerce) via config flags, not code changes.

---

## Current Architecture

```
                         Internet
                             │
                    ┌────────▼────────┐
                    │   API Gateway   │  (future — not implemented)
                    └────────┬────────┘
                             │
               ┌─────────────▼─────────────┐
               │     Auth Service (Go)      │
               │  Chi Router + Middleware   │
               │  ┌─────────┐ ┌─────────┐  │
               │  │ Handler │─│ Service │  │
               │  └─────────┘ └────┬────┘  │
               │               ┌───┴────┐  │
               │               │  Repo  │  │
               └───────────────┴───┬────┘──┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
    ┌─────────▼──────┐  ┌─────────▼──────┐  ┌─────────▼──────┐
    │   PostgreSQL   │  │     Redis      │  │   RabbitMQ     │
    │ Users + Outbox │  │ Sessions/OTP/  │  │ Email events   │
    │                │  │ Rate limits    │  │ (via outbox)   │
    └────────────────┘  └────────────────┘  └────────────────┘
```

### Dependency Injection Chain

```
Config → DB → Redis → Repos → RateLimiter → EmailPublisher
      → JWT/TOTP managers → AuthService → Handlers → Router
      → OutboxRelay (goroutine)
```

---

## Implemented Features

### Authentication Methods

| Method | Status | Endpoints |
|--------|--------|-----------|
| Email + Password | ✅ | `POST /api/v1/auth/login` |
| Email OTP | ✅ | `POST /api/v1/auth/request-otp` → `POST /api/v1/auth/verify-login` |
| Email Signup + Verify | ✅ | `POST /api/v1/auth/signup` → `POST /api/v1/auth/verify-signup` |
| TOTP 2FA | ✅ | Setup/confirm/verify/disable endpoints |
| Phone SMS OTP | ⚠️ Partial | SMS client stubbed; `enable_phone_auth` flag exists |
| OAuth2 / OIDC | ❌ | Not implemented |
| WebAuthn / Passkeys | ❌ | Not implemented |

### Security

| Feature | Status | Notes |
|---------|--------|-------|
| bcrypt password hashing | ✅ | Cost factor 10 |
| RS256 JWT (RSA-2048) | ✅ | Asymmetric — public key exposed for downstream verification |
| JWT blacklist (per-token) | ✅ | Redis key `blacklist:jwt:{jti}` with remaining TTL |
| JWT user-level revocation | ✅ | Redis key `blacklist:user:{userID}` — invalidates all tokens issued before timestamp |
| Refresh token rotation | ✅ | JTI tracked in Redis; deleted on use |
| Login attempt tracking | ✅ | Redis Hash per email + per IP |
| Account lockout | ✅ | Configurable threshold + duration; checked before password verify |
| OTP hashed before storage | ✅ | SHA-256 in Redis |
| TOTP secret encrypted | ✅ | AES-256-GCM; base64 key in config |
| Rate limiting — global | ✅ | Sliding window, per IP |
| Rate limiting — per endpoint | ✅ | Login (IP+email dual), signup, OTP, refresh, 2FA, authenticated |
| RBAC | ✅ | `RequireRole` / `RequireAdmin` middleware; roles in JWT claims |
| Audit log | ✅ | DB table; guarded by `enable_audit_log` flag |
| Password reset | ✅ | Token-based, email delivery via outbox |
| Password change | ✅ | Revokes all existing sessions |
| Session listing | ✅ | Returns active refresh token JTIs |
| Session revocation | ✅ | Admin or self; removes specific JTI from Redis |
| Soft delete | ✅ | GDPR-friendly |
| Anti-enumeration | ✅ | Forgot-password always returns 200 |

### Infrastructure

| Feature | Status | Notes |
|---------|--------|-------|
| Transactional outbox | ✅ | email_outbox table → OutboxRelay → RabbitMQ |
| Graceful shutdown | ✅ | 15s context timeout |
| Structured logging | ✅ | Logrus JSON |
| Request ID propagation | ✅ | Chi middleware |
| Swagger docs | ✅ | `swag init` → `docs/` |
| Docker compose (dev) | ✅ | postgres + redis + rabbitmq + redis-insight + service |
| Docker compose (staging/prod) | ✅ | Separate files with resource limits |
| Database migrations | ✅ | Separate `migrate` binary with up/down/seed |
| Health check endpoints | ✅ | `GET /livez` (liveness), `GET /readyz` (readiness), `GET /health` (full diagnostics) |

### User Management (Admin API)

| Endpoint | Status |
|----------|--------|
| List users (paginated, filterable) | ✅ |
| Get user by ID | ✅ |
| Update user (profile + role + metadata) | ✅ |
| Deactivate / Reactivate | ✅ |
| Soft delete | ✅ |
| Unlock account | ✅ |
| List user sessions | ✅ |
| Revoke specific session | ✅ |

---

## Planned / Not Yet Implemented

### P0 — Critical

| Item | Notes |
|------|-------|
| Test suite | Zero coverage. Unit tests for repo, service. Integration tests hitting real DB/Redis. |
| ~~Enhanced health check~~ | ✅ Done — `/livez`, `/readyz`, `/health` implemented in `internal/health/`. |

### P1 — High Priority

| Item | Notes |
|------|-------|
| Prometheus metrics | Request rate, latency histograms, auth event counters (login success/fail, lockouts). |
| OpenTelemetry tracing | Distributed trace context for debugging across services. |
| Phone SMS auth (complete) | SMS client (`internal/client/sms`) is stubbed. Needs real provider wiring (Twilio/Nexmo). |
| Refresh token family tracking | Detect refresh token reuse (rotation theft detection). |
| API Gateway integration | Nginx or Traefik in front for TLS termination + infrastructure-level rate limiting. |

### P2 — Medium Priority

| Item | Notes |
|------|-------|
| OAuth2 / OIDC provider | Issue OAuth2 tokens; support OIDC discovery document. |
| Social login (Google, GitHub) | OAuth2 client for external identity providers. |
| WebAuthn / Passkeys | FIDO2-based passwordless auth. |
| Device fingerprinting | Track device metadata per session; anomaly alerts on new device. |
| Magic link login | Passwordless via email token. |
| Risk scoring | ML-based anomaly detection (unusual IP, time, device). |
| Multi-tenancy | Namespace users by tenant ID; per-tenant config. |

### P3 — Low Priority / Future

| Item | Notes |
|------|-------|
| Admin UI | Web dashboard for user management. |
| Backup codes for 2FA | One-time recovery codes if TOTP device lost. |
| Email change flow | Verify new email before updating. |
| GDPR export | User data export endpoint. |
| gRPC interface | Internal service-to-service gRPC alternative to HTTP. |

---

## Data Model

### PostgreSQL — `users` table (key columns)

```
id              UUID PK
email           TEXT UNIQUE
phone           TEXT UNIQUE NULLABLE
password_hash   TEXT NULLABLE
name            TEXT
role            TEXT DEFAULT 'user'
is_verified     BOOL
is_active       BOOL DEFAULT true
is_2fa_enabled  BOOL
totp_secret     TEXT NULLABLE (AES-256-GCM encrypted)
failed_login_attempts INT
locked_until    TIMESTAMPTZ NULLABLE
last_login_at   TIMESTAMPTZ NULLABLE
metadata        JSONB (platform-specific data; GIN indexed)
deleted_at      TIMESTAMPTZ NULLABLE (soft delete)
created_at / updated_at TIMESTAMPTZ
```

### PostgreSQL — `email_outbox` table

```
id              UUID PK
idempotency_key TEXT UNIQUE
routing_key     TEXT
event_type      TEXT
payload         JSONB
status          TEXT (pending/published/failed)
attempts        INT
created_at / published_at TIMESTAMPTZ
```

### Redis Key Schema

| Key pattern | Type | TTL | Purpose |
|-------------|------|-----|---------|
| `otp:{email}:{purpose}` | String | `otp_ttl` (5min default) | Hashed OTP |
| `pending_user:{email}` | String (JSON) | 10 min | Pre-verification user |
| `refresh_token:{userID}:{jti}` | String | `refresh_token_ttl` | Active refresh token |
| `2fa_secret:{userID}` | String | 10 min | Temp TOTP secret during setup |
| `2fa_challenge:{token}` | String | `totp_challenge_ttl` (5min) | Challenge → userID |
| `blacklist:jwt:{jti}` | String | Remaining token lifetime | Revoked access token |
| `blacklist:user:{userID}` | String | `refresh_token_ttl` | Per-user bulk revocation timestamp |
| `login_attempts:{type}:{id}` | Hash | 30 min | count, timestamps, locked_until |
| `rl:{prefix}:{key}` | Sorted Set | Auto (window size) | Sliding window rate limit |

---

## API Routes Summary

### Public (no auth required)

```
POST /api/v1/auth/signup
POST /api/v1/auth/verify-signup
POST /api/v1/auth/login
POST /api/v1/auth/request-otp
POST /api/v1/auth/verify-login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
POST /api/v1/auth/forgot-password
POST /api/v1/auth/reset-password
POST /api/v1/auth/2fa/verify
GET  /api/v1/auth/public-key
GET  /livez    — liveness probe (process alive, goroutines ≤ 10 000)
GET  /readyz   — readiness probe (DB + Redis + RabbitMQ reachable)
GET  /health   — full diagnostics (latencies, memory, uptime, build info, outbox lag)
GET  /swagger/*
```

### Authenticated (JWT required)

```
GET  /api/v1/auth/me
POST /api/v1/auth/change-password
POST /api/v1/auth/2fa/setup
POST /api/v1/auth/2fa/confirm
POST /api/v1/auth/2fa/disable
```

### Admin (JWT + admin role required)

```
GET    /api/v1/users/
GET    /api/v1/users/{id}
PUT    /api/v1/users/{id}
DELETE /api/v1/users/{id}
POST   /api/v1/users/{id}/deactivate
POST   /api/v1/users/{id}/reactivate
POST   /api/v1/users/{id}/unlock
```

### Session management (JWT + self-or-admin)

```
GET    /api/v1/users/{id}/sessions
DELETE /api/v1/users/{id}/sessions/{session_id}
```

---

## Configuration Reference

All values configurable via `config.yaml` or env vars (`SECTION_SUBSECTION_KEY`).

### Feature flags (`app.*`)

| Flag | Default | Effect |
|------|---------|--------|
| `enable_email_auth` | true | Allow email+password and email+OTP |
| `enable_phone_auth` | false | Allow phone+SMS OTP (SMS provider must be configured) |
| `enable_password_auth` | true | Allow password-based login |
| `enable_otp_auth` | true | Allow OTP-based login |
| `enable_2fa` | true | Allow TOTP 2FA setup/use |
| `enable_audit_log` | true | Write audit events to DB |
| `require_email_verification` | true | Block login until email verified |
| `require_phone_verification` | false | Block login until phone verified |

### Security defaults

| Setting | Default |
|---------|---------|
| `security.max_login_attempts` | 5 |
| `security.lockout_duration_minutes` | 30 |
| `security.password_min_length` | 8 |
| `security.password_reset_ttl` | 60 min |
| `jwt.access_token_ttl` | 900 sec (15 min) |
| `jwt.refresh_token_ttl` | 604800 sec (7 days) |
| `app.otp_ttl` | 300 sec (5 min) |
| `app.totp_challenge_ttl_sec` | 300 sec (5 min) |

### Rate limit defaults

| Endpoint | Limit | Window |
|----------|-------|--------|
| Global (per IP) | 1000 req | 60 sec |
| Login (per IP) | 10 req | 300 sec |
| Login (per email) | 5 req | 900 sec |
| Signup (per IP) | 3 req | 3600 sec |
| OTP request (per email) | 3 req | 300 sec |
| OTP verify (per email) | 10 req | 600 sec |
| Refresh (per token) | 10 req | 60 sec |
| 2FA setup (per user) | 3 req | 3600 sec |
| 2FA verify (per email) | 5 req | 300 sec |
| Authenticated (per user) | 100 req | 60 sec |

---

## Security Design Decisions

**RS256 over HS256**: Asymmetric signing lets downstream services verify tokens using the public key without sharing a secret. Public key exposed at `/api/v1/auth/public-key`.

**Transactional outbox**: OTP emails written atomically with business data. Prevents lost emails on service crash while keeping auth service decoupled from email delivery.

**Fail-open on Redis errors**: Rate limiting and blacklist checks log errors but allow requests through. Tradeoff: brief Redis outage doesn't lock out users, but security checks are temporarily weakened.

**Dual login rate limit (IP + email)**: IP-only limits are bypassable via proxy rotation. Email-only limits enable DoS of specific accounts. Both together raise the attack cost without blocking legitimate users.

**OTP hashing**: OTPs stored as SHA-256 hashes in Redis. Prevents credential exposure if Redis is compromised.

**TOTP encryption at rest**: AES-256-GCM encryption of TOTP secrets in PostgreSQL. If DB is exfiltrated without the encryption key (stored separately in config/secret manager), secrets are useless.

**Challenge token for 2FA**: After password auth, a short-lived opaque token (not a JWT) is issued. Decouples the 2FA verification step from the password auth step without exposing user identity in the token.
