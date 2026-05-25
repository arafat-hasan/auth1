# Authentication Microservice - Platform-Agnostic

A secure, extensible, and **platform-agnostic** authentication microservice written in Go. Use it for any platform: e-commerce, SaaS, social networks, and more!

## ⚡ Quick Links

- **[Quick Start Guide](./QUICK_START.md)** - Get running in 5 minutes
- **[Platform-Agnostic Guide](./PLATFORM_AGNOSTIC_GUIDE.md)** - Complete documentation
- **[Changes Summary](./CHANGES_SUMMARY.md)** - What's new in v2.0

## 🎯 What's New in v2.0

✅ **Platform-Agnostic Design** - Use for any application  
✅ **Phone Authentication** - SMS OTP support  
✅ **Role-Based Access Control** - Flexible RBAC system  
✅ **User Metadata** - Store platform-specific data  
✅ **Account Locking** - Automatic security lockout  
✅ **Password Reset** - Email/SMS password recovery  
✅ **Audit Logging** - Complete security trail  
✅ **Soft Delete** - GDPR compliance  
✅ **Enhanced Security** - Production-ready features

## 🚀 Features

### Authentication Methods
- ✅ **Email + Password** - Traditional authentication
- ✅ **Phone + Password** - Phone-based authentication
- ✅ **Email OTP** - Passwordless email login
- ✅ **SMS OTP** - Passwordless phone login
- ✅ **2FA/TOTP** - Time-based 2-factor authentication
- ✅ **Password Reset** - Email/SMS recovery

### Security
- ✅ **JWT RS256** - Asymmetric key signing
- ✅ **Account Locking** - Automatic lockout after failed attempts
- ✅ **Password Policy** - Customizable requirements
- ✅ **Audit Logging** - Complete security trail
- ✅ **Session Management** - Multi-device tracking
- ✅ **IP & User Agent** - Tracking and fraud prevention
- ✅ **Refresh Token Rotation** - Enhanced token security

### User Management
- ✅ **Role-Based Access Control (RBAC)** - Flexible permission system
- ✅ **User Metadata** - Platform-specific data storage (JSONB)
- ✅ **Soft Delete** - GDPR compliance
- ✅ **Account Status** - Active/inactive/locked states
- ✅ **Email/Phone Verification** - Separate verification tracking

### Platform Features
- ✅ **Platform-Agnostic** - Use for any application
- ✅ **Feature Flags** - Enable/disable authentication methods
- ✅ **Custom Roles** - Create platform-specific roles
- ✅ **Extensible** - Easy to add new features
- ✅ **Production Ready** - Battle-tested architecture

### Technical
- ✅ **PostgreSQL** - Persistent storage with advanced features
- ✅ **Redis** - Fast temporary state management
- ✅ **Clean Architecture** - Layered design with DI
- ✅ **Comprehensive Logging** - Structured JSON logs
- ✅ **Docker Support** - Production-ready containers
- ✅ **Health Checks** - Built-in monitoring endpoints

## Architecture

The service follows a clean, layered architecture:

```
├── cmd/auth-service/          # Main application entry point
├── internal/
│   ├── app/
│   │   ├── auth/             # Business logic layer
│   │   ├── service/          # Service orchestration
│   │   ├── handler/          # HTTP handlers
│   │   ├── middleware/       # Authentication, logging, CORS
│   │   ├── repo/             # Repository layer (PostgreSQL, Redis)
│   │   └── model/            # Data models (API, Domain, DB)
│   ├── client/email/         # External email service client
│   ├── config/               # Configuration management
│   └── utils/                # Utilities (JWT, crypto, TOTP)
├── assets/                   # JWT keys, templates
├── scripts/                  # Database migrations, setup scripts
└── docs/                     # API documentation
```

## Quick Start

### Prerequisites

- Go 1.21+
- PostgreSQL 12+
- Redis 6+
- OpenSSL (for key generation)

### Setup

1. **Navigate to the auth service** (if using the monorepo):

   ```bash
   cd services/auth-service
   ```
   
   Or clone standalone:
   
   ```bash
   git clone <repository-url>
   cd auth-service
   ```

2. **Generate JWT keys**:

   ```bash
   chmod +x scripts/generate_keys.sh
   ./scripts/generate_keys.sh
   ```

3. **Setup configuration**:

   ```bash
   cp config.example.yaml config.yaml
   # Edit config.yaml with your settings
   ```

4. **Setup database**:

   ```bash
   # Create PostgreSQL database
   psql -U postgres -c "CREATE DATABASE auth_service;"
   
   # Run migrations using the migration script
   ./scripts/migrate.sh init
   ./scripts/migrate.sh up
   ```

5. **Install dependencies**:

   ```bash
   go mod tidy
   ```

6. **Run the service**:

   ```bash
   go run cmd/auth-service/main.go
   ```

### Using Docker Compose

#### Development Environment

For a complete development environment with automatic migrations and seed data:

```bash
# Generate JWT keys first
./scripts/generate_keys.sh

# Copy configuration
cp config.example.yaml config.yaml

# Start all services (migrations run automatically)
docker-compose up -d

# Check logs
docker-compose logs

# Stop services
docker-compose down
```

This will start:

- PostgreSQL (port 5432)
- Redis (port 6379)
- Migration service (runs once to set up database with seed data)
- auth1 service (port 8080)

#### Staging Environment

```bash
# Start staging environment
docker-compose -f docker-compose.yml -f docker-compose.staging.yml up -d

# View logs
docker-compose -f docker-compose.yml -f docker-compose.staging.yml logs
```

#### Production Environment

```bash
# Set required environment variables
export DATABASE_PASSWORD=your-secure-password
export JWT_SECRET=your-jwt-secret

# Start production environment (no seed data)
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

> **Important**: Production environment requires `DATABASE_PASSWORD` and `JWT_SECRET` environment variables to be set for security.

## API Endpoints

### Public Endpoints

All API endpoints are prefixed with `/api/v1`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/signup` | User signup with email verification |
| POST | `/api/v1/auth/verify-signup` | Verify signup OTP and complete registration |
| POST | `/api/v1/auth/login` | Password-based login |
| POST | `/api/v1/auth/request-otp` | Request OTP for login |
| POST | `/api/v1/auth/verify-login` | Verify login OTP |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout and invalidate refresh token |
| GET | `/.well-known/jwks.json` | JWKS public key (RFC 7517) — for downstream services |
| GET | `/api/v1/auth/jwks` | Same JWKS (convenience alias under API prefix) |
| POST | `/api/v1/auth/2fa/verify` | Verify 2FA code during login |

### Protected Endpoints (Require User JWT)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/auth/me` | Get current user information |
| PUT | `/api/v1/auth/me` | Update own profile (name/phone) |
| POST | `/api/v1/auth/change-password` | Change password (revokes all sessions) |
| POST | `/api/v1/auth/2fa/setup` | Setup 2FA for user account |
| POST | `/api/v1/auth/2fa/confirm` | Confirm 2FA setup with TOTP code |
| POST | `/api/v1/auth/2fa/disable` | Disable 2FA for user account |
| POST | `/api/v1/auth/forgot-password` | Request password reset email |
| POST | `/api/v1/auth/reset-password` | Reset password with token from email |

### Service-to-Service Endpoints (Require API Key)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/auth/introspect` | `ApiKey <key>` | RFC 7662 token introspection with blacklist check |

### Admin Endpoints (Require JWT + Admin Role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users/` | List users with pagination/filters |
| GET | `/api/v1/users/{id}` | Get full user detail |
| PUT | `/api/v1/users/{id}` | Update user profile/role/metadata |
| DELETE | `/api/v1/users/{id}` | Soft-delete user + revoke sessions |
| POST | `/api/v1/users/{id}/deactivate` | Deactivate + revoke sessions |
| POST | `/api/v1/users/{id}/reactivate` | Reactivate user |
| POST | `/api/v1/users/{id}/unlock` | Clear lockout |
| GET | `/api/v1/users/{id}/sessions` | List active sessions (admin or self) |
| DELETE | `/api/v1/users/{id}/sessions/{session_id}` | Revoke specific session (admin or self) |

### Health Check

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health status |
| GET | `/livez` | Liveness probe |
| GET | `/readyz` | Readiness probe |

## Service Integration

This auth service is designed to work with any downstream service (order service, inventory service, etc.) using standard JWT patterns. No SDK required.

### How It Works

Tokens use **RS256 (RSA asymmetric signing)**. The auth service holds the private key; downstream services only need the public key to verify tokens locally — no per-request call to the auth service.

```
Client
  │  Bearer <access_token>
  ▼
Order Service
  ├── Verify RS256 signature with cached public key  ← local, zero latency
  ├── Check exp / iss / nbf
  └── Extract: sub (userID), email, roles
        │
        │ (sensitive ops only — payment, address change, etc.)
        │  POST /api/v1/auth/introspect
        ▼
  Auth Service
  └── Checks signature + Redis blacklists → { "active": true/false }
```

### Step 1: Fetch Public Key at Startup

```bash
# JWKS format (recommended — works with most JWT libraries)
curl http://auth-service:8080/.well-known/jwks.json

```

JWKS response:
```json
{
  "keys": [{
    "kty": "RSA", "use": "sig", "alg": "RS256",
    "kid": "Xk3mN9pQ",
    "n": "<base64url modulus>",
    "e": "AQAB"
  }]
}
```

Cache the key by `kid`. Re-fetch when you see a `kid` you don't recognize (key rotation).

### Step 2: Validate Tokens Locally

```go
// Example: Go order service middleware
import "github.com/golang-jwt/jwt/v5"

type Claims struct {
    Sub   string   `json:"sub"`    // userID — use this as canonical user identity
    Email string   `json:"email"`
    Roles []string `json:"roles"`
    jwt.RegisteredClaims
}

func validateToken(tokenStr string, publicKey *rsa.PublicKey) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected alg: %v", t.Header["alg"])
        }
        return publicKey, nil
    })
    if err != nil {
        return nil, err
    }
    return token.Claims.(*Claims), nil
}
```

**Always use `sub` (userID UUID) as the user identity — never `email`, which can change.**

### Step 3: Call Introspect for Sensitive Operations

Configure a service API key in auth service `config.yaml`:

```yaml
services:
  allowed_api_keys:
    - "your-order-service-key"   # generate: openssl rand -hex 32
```

Then call introspect for high-value operations (payment, checkout):

```bash
curl -X POST http://auth-service:8080/api/v1/auth/introspect \
  -H "Authorization: ApiKey your-order-service-key" \
  -H "Content-Type: application/json" \
  -d '{"token": "<access_token>"}'
```

Response when valid:
```json
{
  "active": true,
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "roles": ["user"],
  "exp": 1716681600,
  "iat": 1716680700,
  "iss": "auth1",
  "jti": "..."
}
```

Response when invalid/revoked:
```json
{ "active": false }
```

### Trade-offs

| Approach | Latency | Revocation |
|---|---|---|
| Local validation only | Zero overhead | 15 min gap (access token TTL) |
| Local + introspect on sensitive ops | One extra call for high-value ops | Immediate |
| Introspect on every request | +network RTT per request | Immediate — but defeats the purpose of JWTs |

The recommended pattern is **local validation for most requests, introspect for sensitive operations**. This is the same model used by Auth0, AWS Cognito, and Keycloak.

## API Usage Examples

### Signup Flow

1. **Start signup**:

   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/signup \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "name": "John Doe",
       "password": "password123"
     }'
   ```

2. **Verify signup with OTP**:

   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/verify-signup \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "otp": "123456"
     }'
   ```

### Login Flow

1. **Password login**:

   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "password123"
     }'
   ```

2. **OTP login**:

   ```bash
   # Request OTP
   curl -X POST http://localhost:8080/api/v1/auth/request-otp \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "purpose": "login"
     }'

   # Verify OTP
   curl -X POST http://localhost:8080/api/v1/auth/verify-login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "otp": "123456"
     }'
   ```

### Quick Test with Seeded Data

For development environment, you can test with the pre-seeded admin user:

```bash
# Login with development admin
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@authservice.dev",
    "password": "admin123"
  }'
```

### Protected Endpoints

```bash
# Get user info
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer <access_token>"

# Setup 2FA
curl -X POST http://localhost:8080/api/v1/auth/2fa/setup \
  -H "Authorization: Bearer <access_token>"
```

## Configuration

The service can be configured via YAML file, environment variables, or command-line flags. Environment variables override file configuration.

Key configuration options:

```yaml
server:
  host: "0.0.0.0"
  port: "8080"

database:
  host: "localhost"
  port: "5432"
  user: "auth1"
  password: "password"
  name: "auth1"

redis:
  host: "localhost"
  port: "6379"

jwt:
  access_token_ttl: 900      # 15 minutes
  refresh_token_ttl: 604800  # 7 days

email:
  service_url: "http://localhost:8081"
  timeout: 30
  retry_count: 3

app:
  log_level: "info"
  otp_length: 6
  otp_ttl: 300               # 5 minutes
```

## Environment Variables

### Core Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_ENVIRONMENT` | Environment (development/staging/production) | `development` |
| `SERVER_HOST` | Server host | `0.0.0.0` |
| `SERVER_PORT` | Server port | `8080` |
| `DATABASE_HOST` | PostgreSQL host | `localhost` |
| `DATABASE_PORT` | PostgreSQL port | `5432` |
| `DATABASE_USER` | Database user | `auth1` |
| `DATABASE_PASSWORD` | Database password | `password` |
| `DATABASE_NAME` | Database name | `auth1` |
| `DATABASE_SSL_MODE` | PostgreSQL SSL mode | `disable` |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `APP_LOG_LEVEL` | Log level | `info` |

### Security Configuration (Production Required)

| Variable | Description | Required |
|----------|-------------|----------|
| `JWT_SECRET` | JWT signing secret | **Production** |

### Environment-Specific Defaults

**Development:**

- `APP_LOG_LEVEL=debug`
- `DATABASE_SSL_MODE=disable`
- Seed data enabled

**Staging:**

- `APP_LOG_LEVEL=debug`
- `DATABASE_SSL_MODE=disable`
- Limited seed data

**Production:**

- `APP_LOG_LEVEL=info`
- `DATABASE_SSL_MODE=require`
- No seed data
- Requires secure passwords and JWT secrets

## Email Service Integration

The service integrates with an external email service via HTTP. The email service should implement:

```text
POST /email/send
Content-Type: application/json

{
  "to": "user@example.com",
  "subject": "Your OTP Code",
  "template": "otp_email",
  "variables": {
    "otp": "123456",
    "expiry": "5 minutes"
  }
}
```

## Database Migrations

The service uses a production-grade migration system built with Bun's migration features:

### Features

- **Up/Down migrations**: Forward and rollback capabilities with safety checks
- **Environment-aware**: Different behavior for dev/staging/production
- **Seed data management**: Environment-specific seed data
- **Transaction support**: Atomic migration execution
- **CLI management**: Easy command-line interface with safety guards
- **Status tracking**: View migration history and status
- **Production safety**: Prevents dangerous operations in production

### Migration Commands

#### Basic Operations

```bash
# Initialize migration tracking
./scripts/migrate.sh init

# Run pending migrations
./scripts/migrate.sh up

# Check migration status
./scripts/migrate.sh status

# Rollback last migration group (not allowed in production)
./scripts/migrate.sh down

# Create new migration
./scripts/migrate.sh create migration_name
```

#### Environment-Specific Operations

```bash
# Run environment-specific seed data
./scripts/migrate.sh seed

# Production-ready deployment sequence (init + up + conditional seeding)
./scripts/migrate.sh deploy

# Specify environment explicitly
./scripts/migrate.sh -e production deploy
./scripts/migrate.sh -e staging seed
./scripts/migrate.sh -e development up
```

#### Advanced Operations

```bash
# Reset database (development only - not allowed in production)
./scripts/migrate.sh reset

# Production deployment (safe sequence)
./scripts/migrate.sh -e production deploy
```

### Environment Behavior

| Environment | Init | Up | Seed Data | Down/Reset |
|-------------|------|-------|-----------|------------|
| **Development** | ✅ | ✅ | Admin + Test Users | ✅ Allowed |
| **Staging** | ✅ | ✅ | Admin Only | ✅ Allowed |
| **Production** | ✅ | ✅ | None | ❌ Blocked |

### Docker Integration

Migrations run automatically when using Docker Compose:

- **Development**: Runs `init`, `up`, and `seed`
- **Staging**: Runs `init`, `up`, and `seed` (staging admin)
- **Production**: Runs `init` and `up` only (no seed data)

### Seed Data

The system provides environment-specific seed data:

**Development Environment:**

- `admin@authservice.dev` (password: `admin123`) - Verified admin user
- `user1@authservice.dev`, `user2@authservice.dev`, `user3@authservice.dev` - Test users

**Staging Environment:**

- `admin@staging.authservice.com` (password: `admin123`) - Staging admin

**Production Environment:**

- No seed data (manual user creation required)

For more details, see [migrations/README.md](migrations/README.md).

## Security Features

- **JWT RS256**: Asymmetric key signing for tokens
- **Password Hashing**: bcrypt with configurable cost
- **OTP Security**: SHA-256 hashed OTPs with TTL
- **2FA Support**: TOTP-based two-factor authentication
- **Token Rotation**: Refresh tokens are rotated on use
- **Rate Limiting**: OTP request rate limiting
- **CORS**: Configurable CORS policies
- **Secure Headers**: Security middleware included

## Development

### Project Structure

- **Clean Architecture**: Domain-driven design with clear separation
- **Dependency Injection**: All dependencies are injected
- **Interface-based**: Repository and service interfaces for testing
- **Error Handling**: Comprehensive error handling and logging
- **Validation**: Input validation with Gin binding
- **Testing**: Unit tests with mocks (structure provided)

### Running Tests

```bash
go test ./...
```

### Building

```bash
# Local build
go build -o auth-service ./cmd/auth-service

# Docker build
docker build -t auth1:latest .
```

## Deployment

### Development Environment

```bash
# Quick start with Docker Compose
./scripts/generate_keys.sh
cp config.example.yaml config.yaml
docker-compose up -d

# View service logs
docker-compose logs auth-service

# Test the service
curl http://localhost:8080/health
```

### Staging Environment

```bash
# Start staging environment
docker-compose -f docker-compose.yml -f docker-compose.staging.yml up -d

# Or with custom environment variables
DATABASE_PASSWORD=staging-password \
DATABASE_NAME=auth1_staging \
docker-compose -f docker-compose.yml -f docker-compose.staging.yml up -d
```

### Production Environment

#### Using Docker Compose (Recommended)

```bash
# Set required production environment variables
export DATABASE_PASSWORD=your-secure-database-password
export JWT_SECRET=your-jwt-secret-key
export DATABASE_USER=auth1_prod
export DATABASE_NAME=auth1_prod

# Deploy to production
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Verify deployment
docker-compose -f docker-compose.yml -f docker-compose.prod.yml logs
curl http://localhost:8080/health
```

#### Using Docker

```bash
docker run -d \
  --name auth1 \
  -p 8080:8080 \
  -e APP_ENVIRONMENT=production \
  -e DATABASE_HOST=your-db-host \
  -e DATABASE_PASSWORD=secure-password \
  -e JWT_SECRET=your-jwt-secret \
  -e REDIS_HOST=your-redis-host \
  -v /path/to/assets:/root/assets \
  auth1:latest
```

#### Production Checklist

- [ ] Set strong `DATABASE_PASSWORD`
- [ ] Generate secure `JWT_SECRET` (use `openssl rand -base64 32`)
- [ ] Enable SSL (`DATABASE_SSL_MODE=require`)
- [ ] Use production log level (`APP_LOG_LEVEL=info`)
- [ ] Configure proper firewall rules
- [ ] Set up monitoring and health checks
- [ ] Backup database regularly
- [ ] Rotate JWT keys periodically

### Kubernetes

Example Kubernetes manifests are available in the `docs/k8s/` directory.

## Monitoring

The service provides:

- Structured JSON logging
- Health check endpoint (`/health`)
- Metrics (ready for Prometheus integration)
- Request/response logging
- Error tracking

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 