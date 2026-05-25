# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build ./...
go build -o auth-service ./cmd/auth-service/
go build -o migrate ./migrations/

# Run
./auth-service                        # requires config.yaml and assets/

# Migrations (separate binary)
./migrate init                        # initialize tracking table
./migrate up                          # run pending migrations
./migrate down                        # rollback last group
./migrate status                      # show applied/pending
./migrate create <name>               # scaffold new migration
./migrate seed                        # seed based on APP_ENVIRONMENT

# Generate RSA keys (required before first run)
./scripts/generate_keys.sh            # outputs to assets/private_key.pem + public_key.pem

# Docker (dev stack: postgres, redis, rabbitmq, redis-insight, migrations, auth-service)
docker compose up -d
docker compose logs -f auth-service

# Swagger docs (must install swag first: go install github.com/swaggo/swag/cmd/swag@latest)
swag init -g cmd/auth-service/main.go -o docs/

# Lint
go vet ./...
```

## Architecture

Single binary HTTP service. Entry point: `cmd/auth-service/main.go`. Separate migration binary: `migrations/main.go`.

### Dependency wiring (main.go top-to-bottom)

1. Config (`internal/config`) — viper + YAML `config.yaml`, env vars override via `SECTION_SUBSECTION_KEY` convention
2. PostgreSQL via `uptrace/bun` + pgdriver
3. Redis via `go-redis/v9`
4. Repositories (`internal/app/repo`) — UserRepo (postgres), RedisRepo (redis), OutboxRepo (postgres)
5. Rate limiter (`internal/ratelimit`) — sliding window via Redis sorted sets
6. EmailPublisher (`internal/publisher`) — `OutboxWriter` writes to `email_outbox` table
7. JWT + TOTP managers (`internal/utils`)
8. `AuthService` (`internal/service`) — assembled from all deps above
9. Chi router + middleware + `AuthHandler` + `UserHandler` (`internal/app/handler/v1`)
10. `OutboxRelay` worker (`internal/worker`) — goroutine that polls `email_outbox` and publishes to RabbitMQ

### Auth flows

- **Signup**: `POST /api/v1/auth/signup` → OTP emailed → `POST /api/v1/auth/verify-signup` → tokens
- **Password login**: `POST /api/v1/auth/login` → tokens (or 202 + challenge token if 2FA enabled)
- **OTP login**: `POST /api/v1/auth/request-otp` → `POST /api/v1/auth/verify-login` → tokens
- **2FA login**: Login returns 202 with `challenge_token` → `POST /api/v1/auth/2fa/verify` (challenge_token + TOTP code) → tokens
- **2FA setup**: `POST /api/v1/auth/2fa/setup` (auth required) → scan QR → `POST /api/v1/auth/2fa/confirm` (TOTP code)
- **Password reset**: `POST /api/v1/auth/forgot-password` → email link → `POST /api/v1/auth/reset-password`
- **Password change**: `POST /api/v1/auth/change-password` (auth required) — revokes all sessions
- **Token refresh**: `POST /api/v1/auth/refresh` (refresh token in body)
- **Logout**: `POST /api/v1/auth/logout` — deletes refresh token JTI from Redis; access token blacklisted

### Downstream service integration (service-to-service)

RS256 asymmetric signing means downstream services validate tokens **locally** without calling the auth service per-request.

**Primary flow (stateless local validation):**
1. Downstream service fetches `GET /.well-known/jwks.json` once at startup; caches the `kid`→public-key mapping.
2. On each request, the service validates JWT signature + `exp`/`iss`/`nbf` locally.
3. Extracts `sub` (userID), `email`, `roles` from claims for authorization decisions.

**Revocation check flow (sensitive operations only):**
- `POST /api/v1/auth/introspect` — validates signature **and** checks Redis blacklists (per-token JTI + user-level).
- Protected by `Authorization: ApiKey <key>` (not user JWT). Configure keys in `services.allowed_api_keys`.
- Returns RFC 7662: `{ "active": true|false, sub, email, roles, exp, iat, iss, jti }`.
- Use for high-value ops (payment, address change). Skip for read operations — 15 min TTL limits the risk window.

**Key endpoints for downstream services:**

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /.well-known/jwks.json` | None | Public key in JWKS format (RFC 7517) — cache at startup |
| `GET /api/v1/auth/jwks` | None | Same JWKS (convenience alias under API prefix) |
| `POST /api/v1/auth/introspect` | `ApiKey <key>` | Full token validation including revocation state |

### JWT and token management

RSA-2048 (RS256). Access token TTL default 15 min, refresh 7 days. Per-token JTI stored in Redis for refresh token tracking and individual revocation. Public key at `GET /api/v1/auth/public-key` for downstream services. On logout, the access token JTI is blacklisted in Redis with its remaining TTL; the refresh token key is deleted. On password change, `BlacklistAllUserJWTs` sets a user-level blacklist marker that the auth middleware checks.

### Rate limiting

`internal/ratelimit.RateLimiter` uses Redis sorted sets (sliding window). Applied per-endpoint in `main.go` using `appMiddleware.RateLimit`. All limits configurable via `config.yaml` under `rate_limit.*`. Key strategies:
- Global: per IP across all endpoints
- Login: dual limit — by IP and by email (prevents both brute force and credential stuffing)
- OTP endpoints: by email
- Authenticated endpoints: by user ID
- 2FA setup: stricter per-user limit

### Transactional outbox

Email delivery decoupled: service writes to `email_outbox` table in same DB transaction as business data. `OutboxRelay` goroutine polls that table and publishes to RabbitMQ topic exchange. Idempotency key prevents duplicate inserts. `amqp.max_attempts` controls retry cap. Fail-safe: RabbitMQ downtime doesn't affect user-facing operations.

### TOTP / 2FA

TOTP secrets encrypted with AES-256-GCM before DB storage (`app.totp_encryption_key` = base64-encoded 32-byte key). During setup, plaintext secret stored in Redis with short TTL; moved to encrypted DB on `Confirm2FASetup`. Login with 2FA enabled: password auth succeeds → short-lived challenge token stored in Redis → returned as 202 → client submits challenge token + TOTP code to `/2fa/verify` → tokens issued.

### User management (admin API)

`UserHandler` at `/api/v1/users/` — all routes require JWT auth. Admin-only routes additionally require `RequireAdmin` RBAC middleware.

- `GET /api/v1/users/` — list with pagination + search/role/active filters
- `GET /api/v1/users/{id}` — full admin detail
- `PUT /api/v1/users/{id}` — update profile, role, metadata (all optional fields)
- `DELETE /api/v1/users/{id}` — soft delete + revoke all sessions
- `POST /api/v1/users/{id}/deactivate` — deactivate + revoke sessions
- `POST /api/v1/users/{id}/reactivate`
- `POST /api/v1/users/{id}/unlock` — clear lockout
- `GET /api/v1/users/{id}/sessions` — list active refresh token JTIs (admin or self)
- `DELETE /api/v1/users/{id}/sessions/{session_id}` — revoke specific session (admin or self)

### Model layers

- `internal/app/model/domain` — business entities (`User`, `TokenPair`, `TOTPSetupData`, `PendingUser`)
- `internal/app/model/db` — bun ORM structs (`User` + `EmailOutbox`)
- `internal/app/model/api` — HTTP request/response types with `validate:` tags

### Configuration

`config.yaml` (see `config.example.yaml`). Env vars override via `DATABASE_HOST`, `REDIS_HOST`, `AMQP_URL`, etc. Key sections:

| Section | Purpose |
|---------|---------|
| `server.*` | Host, port |
| `database.*` | PostgreSQL connection |
| `redis.*` | Redis connection |
| `jwt.*` | Key paths, token TTLs |
| `amqp.*` | RabbitMQ URL, exchange, outbox poll interval |
| `sms.*` | SMS provider (phone auth, currently unused) |
| `security.*` | Login lockout, password policy, reset TTL |
| `app.*` | Feature flags, OTP config, TOTP encryption key |
| `rate_limit.*` | Per-endpoint limits and windows |
| `services.*` | `allowed_api_keys` list for `/introspect` endpoint |

Feature flags under `app.*`: `enable_email_auth`, `enable_phone_auth`, `enable_password_auth`, `enable_otp_auth`, `enable_2fa`, `enable_audit_log`, `require_email_verification`, `require_phone_verification`.

### Key files

| Path | Purpose |
|------|---------|
| `cmd/auth-service/main.go` | Entry point: wiring, routing, graceful shutdown |
| `internal/config/config.go` | Config structs + viper loading + JWT key loading |
| `internal/service/auth_service.go` | `AuthService` interface (all methods) |
| `internal/service/service.go` | `authServiceImpl` + shared helpers (`generateTokens`, `generateAndSendOTP`, `verifyOTP`, `auditLog`) |
| `internal/service/login.go` | Login, lockout tracking, 2FA challenge issuance |
| `internal/service/registration.go` | Signup + verify flows |
| `internal/service/token.go` | Refresh + logout + logout-all |
| `internal/service/twofa.go` | TOTP setup/confirm/verify-login/disable |
| `internal/service/password.go` | Password reset + change (with session revocation) |
| `internal/service/user.go` | User CRUD, role/metadata updates, session management |
| `internal/service/introspect.go` | `GetJWKS()` + `IntrospectToken()` implementation |
| `internal/service/config.go` | `service.Config` struct (TTLs, feature flags, encryption key) |
| `internal/service/dto.go` | Service-layer request/response types |
| `internal/app/handler/v1/auth_handler.go` | Auth HTTP handlers |
| `internal/app/handler/v1/user_handler.go` | Admin user management HTTP handlers |
| `internal/app/middleware/auth_chi.go` | JWT auth middleware (blacklist + user-level revocation check) |
| `internal/app/middleware/api_key.go` | `RequireServiceAPIKey` middleware for `/introspect` |
| `internal/app/middleware/rate_limit.go` | Rate limit middleware + key functions (IP, email, token, user) |
| `internal/app/middleware/rbac.go` | `RequireRole` / `RequireAdmin` RBAC middleware |
| `internal/app/repo/redis_repository.go` | All Redis ops: OTP, refresh tokens, 2FA, blacklist, login attempts |
| `internal/app/repo/user_repository.go` | PostgreSQL user CRUD + audit log |
| `internal/app/repo/outbox_repository.go` | Email outbox read/write |
| `internal/ratelimit/rate_limiter.go` | Sliding window rate limiter using Redis sorted sets |
| `internal/publisher/outbox_writer.go` | `OutboxWriter` — writes email events to DB outbox |
| `internal/worker/outbox_relay.go` | Polls outbox, publishes to RabbitMQ |
| `internal/utils/jwt.go` | JWT generation + validation (RS256) |
| `internal/utils/totp.go` | TOTP secret gen + AES-256-GCM encryption/decryption |
| `internal/utils/crypto.go` | OTP generation + SHA-256 hashing |
| `internal/utils/password.go` | bcrypt hash + verify |
| `internal/utils/rbac.go` | Role helpers |
| `assets/private_key.pem` | RSA private key — never commit real keys |
| `migrations/` | Bun migration files + separate `migrate` binary |

### Redis key schema

| Pattern | Type | Purpose |
|---------|------|---------|
| `otp:{email}:{purpose}` | String | Hashed OTP (TTL = otp_ttl) |
| `pending_user:{email}` | String (JSON) | Pre-verification user data |
| `refresh_token:{userID}:{jti}` | String | Active refresh token marker |
| `2fa_secret:{userID}` | String | Temp TOTP secret during setup |
| `2fa_challenge:{token}` | String | Challenge token → userID (short TTL) |
| `blacklist:jwt:{jti}` | String | Blacklisted access token (TTL = remaining lifetime) |
| `blacklist:user:{userID}` | String | Timestamp: all tokens before this are invalid |
| `login_attempts:{type}:{identifier}` | Hash | Failed attempt tracking (count, timestamps, locked_until) |
| `rl:{prefix}:{key}` | Sorted Set | Rate limit sliding window (score = timestamp) |
