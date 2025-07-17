# auth1 - Authentication Microservice

A secure and extensible authentication microservice written in Go, providing JWT-based authentication with email/phone signup, OTP verification, and TOTP-based 2FA.

## Features

- **User Authentication**: Email/phone-based signup with password or OTP-based login
- **JWT Tokens**: RS256 signed access and refresh tokens
- **Two-Factor Authentication**: TOTP-based 2FA support
- **OTP Verification**: Email-based OTP for signup and login verification
- **Redis Integration**: For temporary authentication state (OTP, tokens, pending users)
- **PostgreSQL**: For persistent user data storage
- **External Email Service**: HTTP-based email service integration
- **Clean Architecture**: Layered design with separation of concerns
- **Comprehensive Logging**: Structured logging with Logrus
- **Health Checks**: Built-in health check endpoints
- **Docker Support**: Ready for containerized deployment

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

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd auth1
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
   psql -U postgres -c "CREATE DATABASE auth1;"
   
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

For a complete development environment:

```bash
# Generate JWT keys first
./scripts/generate_keys.sh

# Copy configuration
cp config.example.yaml config.yaml

# Start all services
docker-compose up -d
```

This will start:
- PostgreSQL (port 5432)
- Redis (port 6379)
- Migration service (runs once to set up database)
- auth1 service (port 8080)

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/signup` | User signup with email verification |
| POST | `/auth/verify-signup` | Verify signup OTP and complete registration |
| POST | `/auth/login` | Password-based login |
| POST | `/auth/request-otp` | Request OTP for login |
| POST | `/auth/verify-login` | Verify login OTP |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/logout` | Logout and invalidate refresh token |
| GET | `/auth/public-key` | Get JWT public key for verification |
| POST | `/auth/2fa/verify` | Verify 2FA code during login |

### Protected Endpoints (Require Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/me` | Get current user information |
| POST | `/auth/2fa/setup` | Setup 2FA for user account |
| POST | `/auth/2fa/disable` | Disable 2FA for user account |

### Health Check

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health status |

## API Usage Examples

### Signup Flow

1. **Start signup**:
   ```bash
   curl -X POST http://localhost:8080/auth/signup \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "name": "John Doe",
       "password": "securepassword123"
     }'
   ```

2. **Verify signup with OTP**:
   ```bash
   curl -X POST http://localhost:8080/auth/verify-signup \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "otp": "123456"
     }'
   ```

### Login Flow

1. **Password login**:
   ```bash
   curl -X POST http://localhost:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "securepassword123"
     }'
   ```

2. **OTP login**:
   ```bash
   # Request OTP
   curl -X POST http://localhost:8080/auth/request-otp \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "purpose": "login"
     }'

   # Verify OTP
   curl -X POST http://localhost:8080/auth/verify-login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "otp": "123456"
     }'
   ```

### Protected Endpoints

```bash
# Get user info
curl -X GET http://localhost:8080/auth/me \
  -H "Authorization: Bearer <access_token>"

# Setup 2FA
curl -X POST http://localhost:8080/auth/2fa/setup \
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

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_HOST` | Server host | `0.0.0.0` |
| `SERVER_PORT` | Server port | `8080` |
| `DATABASE_HOST` | PostgreSQL host | `localhost` |
| `DATABASE_PORT` | PostgreSQL port | `5432` |
| `DATABASE_USER` | Database user | `auth1` |
| `DATABASE_PASSWORD` | Database password | `password` |
| `DATABASE_NAME` | Database name | `auth1` |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `APP_LOG_LEVEL` | Log level | `info` |

## Email Service Integration

The service integrates with an external email service via HTTP. The email service should implement:

```
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

The service uses a robust migration system built with Bun's migration features:

### Features
- **Up/Down migrations**: Forward and rollback capabilities
- **Transaction support**: Atomic migration execution
- **Seed data**: Initial data seeding for development
- **CLI management**: Easy command-line interface
- **Status tracking**: View migration history and status

### Usage

```bash
# Initialize migration tracking
./scripts/migrate.sh init

# Run pending migrations
./scripts/migrate.sh up

# Check migration status
./scripts/migrate.sh status

# Rollback last migration group
./scripts/migrate.sh down

# Create new migration
./scripts/migrate.sh create migration_name
```

### Docker Integration
Migrations run automatically when using Docker Compose, ensuring your database is always up-to-date.

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

### Docker

```bash
docker run -d \
  --name auth1 \
  -p 8080:8080 \
  -e DATABASE_HOST=your-db-host \
  -e REDIS_HOST=your-redis-host \
  -v /path/to/config.yaml:/root/config.yaml \
  -v /path/to/assets:/root/assets \
  auth1:latest
```

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