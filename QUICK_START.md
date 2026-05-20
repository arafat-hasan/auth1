# Quick Start Guide - Platform-Agnostic Auth Service

Get up and running in 5 minutes!

## Prerequisites

- Docker & Docker Compose installed
- Or: Go 1.21+, PostgreSQL 15+, Redis 7+

---

## Option 1: Docker Compose (Recommended)

### Step 1: Clone and Configure

```bash
cd services/auth-service

# Generate JWT keys
./scripts/generate_keys.sh

# Copy and edit configuration
cp config.example.yaml config.yaml
```

### Step 2: Start Services

```bash
# Start PostgreSQL, Redis, and auth service
docker-compose up -d

# View logs
docker-compose logs -f auth-service
```

### Step 3: Verify

```bash
# Health check
curl http://localhost:8080/health

# Expected response:
# {"status":"healthy","service":"auth-service","version":"2.0.0"}
```

---

## Option 2: Local Development

### Step 1: Setup

```bash
cd services/auth-service

# Install dependencies
go mod tidy

# Generate JWT keys
./scripts/generate_keys.sh

# Configure
cp config.example.yaml config.yaml
# Edit config.yaml with your PostgreSQL and Redis settings
```

### Step 2: Database Migration

```bash
# Initialize migrations
./scripts/migrate.sh init

# Run migrations
./scripts/migrate.sh up

# Optional: Load seed data (development only)
./scripts/migrate.sh seed
```

### Step 3: Run

```bash
# Start the service
go run cmd/auth-service/main.go

# Or build and run
go build -o auth-service ./cmd/auth-service
./auth-service
```

---

## Basic Usage

### 1. Register a User

```bash
curl -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "name": "John Doe",
    "password": "SecurePass123"
  }'
```

### 2. Verify Email (use OTP from logs in dev mode)

```bash
curl -X POST http://localhost:8080/api/v1/auth/verify-signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "otp": "123456"
  }'
```

### 3. Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123"
  }'
```

Response:
```json
{
  "tokens": {
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc...",
    "expires_in": 900,
    "token_type": "Bearer"
  },
  "user": {
    "id": "uuid",
    "email": "john@example.com",
    "name": "John Doe",
    "role": "user",
    ...
  }
}
```

### 4. Access Protected Endpoint

```bash
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## Platform-Specific Setup

### For Duitara (Matrimony)

Edit `config.yaml`:

```yaml
app:
  name: "duitara-auth"
  enable_phone_auth: true
  require_phone_verification: true

sms:
  service_url: "http://your-sms-service:8082"
  provider: "twilio"
```

Register with phone:

```bash
curl -X POST http://localhost:8080/api/v1/auth/signup-phone \
  -H "Content-Type: application/json" \
  -d '{
    "phone": "+8801712345678",
    "name": "John Doe",
    "password": "SecurePass123",
    "metadata": {
      "user_type": "groom",
      "token_balance": 0
    }
  }'
```

### For E-Commerce

Edit `config.yaml`:

```yaml
app:
  name: "shop-auth"
  enable_phone_auth: false
  require_email_verification: true
  enable_2fa: false
```

### For SaaS

Edit `config.yaml`:

```yaml
app:
  name: "saas-auth"
  enable_2fa: true
  enable_audit_log: true

security:
  max_login_attempts: 5
  password_min_length: 10
  password_require_special: true
```

---

## Common Tasks

### Add Custom Metadata

```bash
curl -X PUT http://localhost:8080/api/v1/users/USER_ID/metadata \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "metadata": {
      "subscription_tier": "premium",
      "custom_field": "value"
    }
  }'
```

### Change User Role

```bash
curl -X PUT http://localhost:8080/api/v1/admin/users/USER_ID/role \
  -H "Authorization: Bearer ADMIN_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role": "moderator"
  }'
```

### Request Password Reset

```bash
curl -X POST http://localhost:8080/api/v1/auth/request-password-reset \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com"
  }'
```

### Setup 2FA

```bash
curl -X POST http://localhost:8080/api/v1/auth/2fa/setup \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## Environment Variables

Override config with environment variables:

```bash
# Database
export DATABASE_HOST=localhost
export DATABASE_PORT=5432
export DATABASE_USER=auth_service
export DATABASE_PASSWORD=yourpassword
export DATABASE_NAME=auth_service

# Redis
export REDIS_HOST=localhost
export REDIS_PORT=6379

# Security
export SECURITY_MAX_LOGIN_ATTEMPTS=5
export SECURITY_LOCKOUT_DURATION_MINUTES=30

# Features
export APP_ENABLE_PHONE_AUTH=true
export APP_ENABLE_2FA=true
```

---

## Testing with Seed Data

In development, use pre-seeded accounts:

```bash
# Login as admin
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@auth-service.dev",
    "password": "admin123"
  }'

# Login as test user
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user1@auth-service.dev",
    "password": "user123"
  }'
```

---

## Troubleshooting

### Issue: Migration fails

**Solution:**
```bash
# Check database connection
psql -h localhost -U auth_service -d auth_service

# Reset migrations (development only!)
./scripts/migrate.sh reset
./scripts/migrate.sh init
./scripts/migrate.sh up
```

### Issue: JWT key error

**Solution:**
```bash
# Regenerate keys
./scripts/generate_keys.sh

# Ensure keys exist
ls -la assets/
# Should see: private_key.pem and public_key.pem
```

### Issue: OTP not received

**Solution:**
- In development, check logs for OTP: `docker-compose logs auth-service | grep OTP`
- In production, verify email/SMS service configuration

### Issue: Account locked

**Solution:**
```bash
# Unlock account (as admin)
curl -X POST http://localhost:8080/api/v1/admin/users/USER_ID/unlock \
  -H "Authorization: Bearer ADMIN_ACCESS_TOKEN"
```

---

## Next Steps

1. **Read Full Documentation:**
   - [Platform-Agnostic Guide](./PLATFORM_AGNOSTIC_GUIDE.md)
   - [Changes Summary](./CHANGES_SUMMARY.md)

2. **Explore Features:**
   - Role-based access control
   - User metadata
   - Audit logging
   - Session management

3. **Configure for Your Platform:**
   - Edit `config.yaml`
   - Set up SMS service (if needed)
   - Customize roles and permissions

4. **Production Deployment:**
   - Use `docker-compose.prod.yml`
   - Set strong passwords
   - Enable SSL/TLS
   - Configure monitoring

---

## API Documentation

- **Swagger UI:** http://localhost:8080/swagger/
- **Health Check:** http://localhost:8080/health
- **JWT Public Key:** http://localhost:8080/api/v1/auth/public-key

---

## Support

- **Documentation:** [PLATFORM_AGNOSTIC_GUIDE.md](./PLATFORM_AGNOSTIC_GUIDE.md)
- **Changes:** [CHANGES_SUMMARY.md](./CHANGES_SUMMARY.md)
- **Issues:** GitHub Issues
- **Email:** support@example.com

---

**Happy Coding! 🚀**

Built with ❤️ for platform-agnostic authentication
