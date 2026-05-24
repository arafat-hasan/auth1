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

1. Config (`internal/config`) — viper + YAML `config.yaml`, env vars override via `SECTION_KEY` convention
2. PostgreSQL via `uptrace/bun` + pgdriver
3. Redis via `go-redis/v9`
4. Repositories (`internal/app/repo`) — UserRepo (postgres), RedisRepo (redis), OutboxRepo (postgres)
5. Rate limiter (`internal/ratelimit`) — sliding window via Redis sorted sets
6. EmailPublisher (`internal/publisher`) — `OutboxWriter` writes to `email_outbox` table
7. JWT + TOTP managers (`internal/utils`)
8. `AuthService` (`internal/service`) — assembled from all deps above
9. Chi router + middleware + `AuthHandler` (`internal/app/handler/v1`)
10. `OutboxRelay` worker (`internal/worker`) — goroutine that polls `email_outbox` and publishes to RabbitMQ

### Transactional outbox pattern

Email delivery is decoupled: service writes to `email_outbox` table (via `OutboxWriter.Enqueue`), `OutboxRelay` polls that table and publishes confirmed messages to RabbitMQ topic exchange `duitara.events`. Idempotency key prevents duplicate inserts. Max retry controlled by `amqp.max_attempts`.

### Rate limiting

`internal/ratelimit.RateLimiter` uses Redis sorted sets (sliding window). Applied per-endpoint in `main.go` using `appMiddleware.RateLimit`. Login has dual limits: by IP and by email. Authenticated endpoints rate-limit by user ID.

### Model layers

- `internal/app/model/domain` — business entities (`User`, `TokenPair`, `TOTPSetupData`)
- `internal/app/model/db` — bun ORM structs (same user shape + `EmailOutbox`)
- `internal/app/model/api` — HTTP request/response types with `validate:` tags

### Auth flows

- **Signup**: POST `/api/v1/auth/signup` → OTP emailed → POST `/api/v1/auth/verify-signup` → tokens
- **Password login**: POST `/api/v1/auth/login` → tokens (or 202 + 2FA challenge if 2FA enabled)
- **OTP login**: POST `/api/v1/auth/request-otp` → POST `/api/v1/auth/verify-login` → tokens
- **2FA**: `POST /api/v1/auth/2fa/verify` completes login after 202 challenge
- **Token refresh**: POST `/api/v1/auth/refresh` (refresh token in body, not cookie)
- **Logout**: invalidates refresh token JTI in Redis; access tokens expire naturally

### JWT

RSA-2048. Access token TTL default 15 min, refresh 7 days. JTI stored in Redis for refresh token rotation and blacklisting. Public key exposed at `GET /api/v1/auth/public-key` for other services to verify tokens without shared secret.

### Configuration

`config.yaml` (see `config.example.yaml`). Environment variables override via `DATABASE_HOST`, `REDIS_HOST`, etc. Feature flags in `app.*`: `enable_email_auth`, `enable_phone_auth`, `enable_password_auth`, `enable_otp_auth`, `enable_2fa`, `require_email_verification`.

### Key files

| Path | Purpose |
|------|---------|
| `internal/service/auth_service.go` | `AuthService` interface |
| `internal/service/service.go` | `authServiceImpl` + shared helpers (`generateTokens`, `generateAndSendOTP`, `verifyOTP`) |
| `internal/service/login.go` | Login + lockout logic |
| `internal/service/registration.go` | Signup + verify flows |
| `internal/service/token.go` | Refresh + logout |
| `internal/service/twofa.go` | TOTP setup/verify/disable |
| `internal/app/middleware/auth_chi.go` | JWT auth middleware (blacklist check via Redis) |
| `internal/app/middleware/rate_limit.go` | Rate limit middleware wiring |
| `assets/private_key.pem` | RSA private key — never commit real keys |
