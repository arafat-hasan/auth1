# Authentication Service - Architecture Enhancement Plan

**Document Version:** 1.0
**Date:** 2026-05-24
**Prepared By:** Solution Architecture Review
**Service:** Platform-Agnostic Authentication Microservice (auth1)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current Architecture Assessment](#current-architecture-assessment)
3. [Architecture Strengths](#architecture-strengths)
4. [Critical Gaps & Security Concerns](#critical-gaps--security-concerns)
5. [Enhancement Recommendations](#enhancement-recommendations)
6. [New Feature Proposals](#new-feature-proposals)
7. [Scalability & Performance Enhancements](#scalability--performance-enhancements)
8. [Security Hardening](#security-hardening)
9. [Operational Excellence](#operational-excellence)
10. [Implementation Roadmap](#implementation-roadmap)
11. [Technical Debt](#technical-debt)
12. [Conclusion](#conclusion)

---

## Executive Summary

### Current State

The **auth1** authentication service is a well-architected, Go-based microservice with strong foundations in:
- Clean architecture with clear separation of concerns
- Transactional outbox pattern for reliable event delivery
- Comprehensive JWT-based authentication with RS256
- Multi-factor authentication (TOTP/2FA)
- RBAC with platform-agnostic design
- Database-first design with proper indexing and migrations

### Key Findings

**✅ Strengths:**
- Production-ready architecture with graceful shutdown
- Strong security primitives (bcrypt, RS256, TOTP)
- Excellent database schema design
- Outbox pattern for event reliability
- Feature flags for flexibility

**⚠️ Critical Gaps:**
- **Missing HTTP endpoints** for implemented features (password reset, user management)
- **No HTTP rate limiting** (critical security vulnerability)
- **Zero test coverage** (high-risk for production)
- **Basic health checks** (no dependency validation)
- **No observability** (metrics, tracing, alerting)

**💡 Opportunities:**
- OAuth2/OIDC provider capabilities
- WebAuthn/Passkeys for passwordless auth
- Advanced security features (anomaly detection, risk scoring)
- Multi-tenancy enhancements
- API rate limiting and DDoS protection

### Priority Recommendations

| Priority | Category | Recommendation | Impact | Effort |
|----------|----------|----------------|--------|--------|
| 🔴 P0 | Security | Implement HTTP rate limiting | Critical | Medium |
| 🔴 P0 | API | Add password reset endpoints | High | Low |
| 🔴 P0 | Quality | Write comprehensive test suite | High | High |
| 🟡 P1 | Operations | Enhanced health checks | Medium | Low |
| 🟡 P1 | Observability | Add Prometheus metrics | High | Medium |
| 🟡 P1 | API | Complete user management endpoints | Medium | Medium |
| 🟢 P2 | Security | Implement anomaly detection | Medium | High |
| 🟢 P2 | Features | Add OAuth2/OIDC provider | High | High |
| 🟢 P2 | Features | WebAuthn/Passkeys support | Medium | High |

---

## Current Architecture Assessment

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         API Gateway (Future)                    │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Auth Service (Go + Chi Router)               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Handlers   │─▶│   Services   │─▶│ Repositories │           │
│  │   (HTTP)     │  │  (Business)  │  │  (Data)      │           │
│  └──────────────┘  └──────────────┘  └──────┬───────┘           │
│                                             │                   │
│  ┌──────────────────────────────────────────┼─────────────┐     │
│  │        Outbox Relay Worker               │             │     │
│  │  ┌───────────────┐         ┌─────────────▼──────────┐  │     │
│  │  │ Poll Outbox   │────────▶│  Publish to RabbitMQ   │  │     │
│  │  └───────────────┘         └────────────────────────┘  │     │
│  └────────────────────────────────────────────────────────┘     │
└──────────┬───────────────────┬───────────────────┬──────────────┘
           │                   │                   │
           ▼                   ▼                   ▼
    ┌──────────┐        ┌──────────┐       ┌──────────┐
    │PostgreSQL│        │  Redis   │       │ RabbitMQ │
    │(Primary) │        │(Cache)   │       │(Events)  │
    └──────────┘        └──────────┘       └──────────┘
                                                   │
                                                   ▼
                                          ┌─────────────────┐
                                          │ Email/SMS       │
                                          │ Workers         │
                                          └─────────────────┘
```

### Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Language** | Go | 1.21+ | Core service |
| **HTTP Router** | Chi | v5 | HTTP routing |
| **Database** | PostgreSQL | 12+ | Primary data store |
| **Cache** | Redis | 6+ | OTP, sessions, rate limiting |
| **Message Queue** | RabbitMQ | 3.x | Event streaming |
| **ORM** | Bun | Latest | Database operations |
| **JWT** | RS256 | - | Token signing |
| **2FA** | TOTP | RFC 6238 | Two-factor auth |
| **Password** | bcrypt | - | Password hashing |
| **Logging** | Logrus | - | Structured logging |
| **Documentation** | Swagger | - | API documentation |

### Data Flow Patterns

#### 1. User Registration Flow
```
Client → POST /signup
  ↓
Handler validates request
  ↓
Service creates pending user in Redis
  ↓
Service writes OTP to Redis (hashed)
  ↓
Service writes email event to DB outbox (transactional)
  ↓
Return 200 to client
  ↓
(Background) Outbox relay polls DB
  ↓
Publish email event to RabbitMQ
  ↓
Email worker sends OTP email
```

#### 2. Authentication Flow (JWT)
```
Client → POST /login (email + password)
  ↓
Handler validates request
  ↓
Service fetches user from PostgreSQL
  ↓
Service verifies password (bcrypt)
  ↓
Service checks 2FA status
  ↓ (if 2FA enabled)
Store temporary auth state in Redis
Return requires_2fa = true
  ↓ (if 2FA disabled)
Generate access token (JWT RS256)
Generate refresh token (UUID)
  ↓
Store refresh token in PostgreSQL + Redis
  ↓
Update last_login_at, ip_address, user_agent
  ↓
Create audit log entry
  ↓
Return tokens to client
```

#### 3. Token Refresh Flow
```
Client → POST /refresh (refresh_token)
  ↓
Handler validates request
  ↓
Service validates refresh token from Redis/PostgreSQL
  ↓
Service checks token expiration
  ↓
Service checks if token is revoked
  ↓
Generate new access token
Rotate refresh token (security best practice)
  ↓
Revoke old refresh token
Store new refresh token
  ↓
Return new tokens to client
```

---

## Architecture Strengths

### 1. Clean Architecture Implementation ✅

**Layered Design:**
```
Handler Layer     → HTTP concerns (request/response, validation)
Service Layer     → Business logic, orchestration
Repository Layer  → Data access, abstraction
Model Layer       → Domain models, API DTOs, DB entities
```

**Benefits:**
- High testability through dependency injection
- Clear separation of concerns
- Easy to swap implementations (e.g., different email providers)
- Maintainable and scalable codebase

**Evidence:**
- All dependencies injected via constructors (no global state)
- Interface-based contracts (`service/service.go`, repositories)
- No circular dependencies

### 2. Transactional Outbox Pattern ✅

**Implementation:**
- Email events written to `email_outbox` table in same transaction as business data
- Background worker (`worker/outbox_relay.go`) polls and publishes to RabbitMQ
- Publisher confirms for reliability
- Retry logic with max attempts

**Benefits:**
- **Prevents message loss** (no events lost on service crash)
- **Eventual consistency** (guaranteed delivery)
- **Decoupling** (auth service doesn't wait for email sending)
- **Fault tolerance** (RabbitMQ downtime doesn't affect user signup)

**Best Practice Alignment:**
- ✅ Follows Microservices Patterns (Chris Richardson)
- ✅ Transactional messaging pattern
- ✅ At-least-once delivery guarantee

### 3. Security Foundations ✅

**Strong Cryptography:**
- JWT signed with **RS256** (asymmetric keys, industry standard)
- Passwords hashed with **bcrypt** (cost factor 10)
- OTPs hashed with **SHA-256** before Redis storage
- TOTP secrets encrypted (RFC 6238 compliant)

**Security Features Implemented:**
- ✅ Account lockout after failed attempts
- ✅ Token rotation (refresh tokens)
- ✅ Token revocation (logout)
- ✅ Session tracking (IP, user agent)
- ✅ Audit logging
- ✅ 2FA/TOTP support
- ✅ Soft delete (GDPR compliance)

### 4. Database Design Excellence ✅

**Schema Quality:**
- Proper normalization
- Comprehensive indexes (including GIN for JSONB)
- Foreign key constraints
- Partial indexes for performance (e.g., active users)
- UUID primary keys (distributed system friendly)
- Timestamp tracking (created_at, updated_at)

**Migration Strategy:**
- Bun migrations with up/down support
- Environment-aware seeding
- Transaction support
- Production safety guards

### 5. Observability Foundations ✅

**Current Implementation:**
- Structured JSON logging (Logrus)
- Request ID propagation
- Request/response logging middleware
- Error tracking with context

**Gaps:**
- ❌ No metrics (Prometheus)
- ❌ No distributed tracing (OpenTelemetry)
- ❌ No alerting

### 6. Platform-Agnostic Design ✅

**Key Features:**
- User metadata (JSONB) for platform-specific data
- Feature flags for authentication methods
- Configurable password policies
- Role-based access control (extensible)
- No hardcoded business logic

**Benefits:**
- Can be used for matrimony apps, e-commerce, SaaS, etc.
- Easy to customize per platform without code changes

---

## Critical Gaps & Security Concerns

### 🔴 Priority 0 (Critical - Address Immediately)

#### 1. Missing HTTP Rate Limiting

**Current State:**
- ❌ No HTTP-level rate limiting middleware
- ❌ Login endpoint vulnerable to brute force
- ❌ Signup endpoint vulnerable to spam
- ❌ Password reset vulnerable to enumeration attacks

**Security Impact:**
- **OWASP Top 10 2021: A04 Insecure Design**
- Attackers can brute force passwords
- Account enumeration via timing attacks
- DoS attacks (resource exhaustion)
- Credential stuffing attacks

**Recommendation:**
Implement multi-layered rate limiting:

1. **Global Rate Limiting** (per IP)
   ```
   100 requests/minute per IP
   1000 requests/hour per IP
   ```

2. **Endpoint-Specific Rate Limiting**
   ```
   /auth/login:         5 attempts/5min per IP, 3 attempts/15min per email
   /auth/signup:        3 signups/hour per IP
   /auth/request-otp:   3 OTPs/5min per email
   /auth/refresh:       10 refreshes/min per token
   ```

3. **Technology Options:**
   - **Redis-based:** `github.com/go-redis/redis_rate` (recommended)
   - **Token bucket algorithm** (standard)
   - **Sliding window log** (accurate)

**Implementation Priority:** 🔴 Immediate (Week 1)

**Estimated Effort:** 2-3 days

**Files to Create:**
- `internal/app/middleware/rate_limit.go`
- `internal/app/repo/rate_limit_repository.go`

---

#### 2. Missing Password Reset Endpoints

**Current State:**
- ✅ Service layer fully implemented (`service/password.go`)
  - `RequestPasswordReset()` ✅
  - `VerifyPasswordResetToken()` ✅
  - `ResetPassword()` ✅
- ❌ No HTTP handlers exposed

**Impact:**
- Critical user experience gap
- Users cannot recover accounts
- Support burden (manual password resets)

**Recommendation:**
Add these endpoints immediately:

```go
POST /api/v1/auth/password/reset-request
Request:
{
  "email": "user@example.com"
}
Response: 200 OK
{
  "message": "Password reset instructions sent to your email"
}

POST /api/v1/auth/password/reset-verify
Request:
{
  "token": "reset-token-from-email",
  "new_password": "NewPassword123!"
}
Response: 200 OK
{
  "message": "Password reset successful"
}

POST /api/v1/auth/password/change (authenticated)
Request:
{
  "current_password": "OldPassword123",
  "new_password": "NewPassword123!"
}
Response: 200 OK
{
  "message": "Password changed successfully"
}
```

**Implementation Priority:** 🔴 Immediate (Week 1)

**Estimated Effort:** 1 day

**Files to Modify:**
- `internal/app/handler/v1/auth_handler.go` (add handlers)
- Update Swagger docs

---

#### 3. Zero Test Coverage

**Current State:**
- ❌ No unit tests
- ❌ No integration tests
- ❌ No end-to-end tests
- ❌ Test files exist but are empty/stubs

**Risk:**
- **High probability of regression bugs**
- Dangerous to refactor
- Cannot confidently deploy changes
- No confidence in security implementations

**Recommendation:**
Implement comprehensive testing strategy:

**Phase 1: Unit Tests (Target: 80% coverage)**
```
Priority 1: Core security functions
- internal/utils/jwt_test.go (token generation, validation)
- internal/utils/password_test.go (hashing, validation)
- internal/utils/totp_test.go (2FA generation, verification)
- internal/utils/crypto_test.go (OTP hashing)

Priority 2: Repository layer
- internal/app/repo/user_repository_test.go
- internal/app/repo/redis_repository_test.go
- Use mock database (sqlmock or testcontainers)

Priority 3: Service layer
- internal/service/registration_test.go
- internal/service/login_test.go
- internal/service/twofa_test.go
- Mock repositories using interfaces
```

**Phase 2: Integration Tests**
```
- Test with real PostgreSQL (Docker Compose)
- Test with real Redis
- Test full auth flows (signup → verify → login → 2FA → logout)
- Test outbox pattern (event publishing)
```

**Phase 3: E2E Tests**
```
- HTTP API tests (real HTTP requests)
- Test all endpoints
- Test error scenarios
- Test rate limiting
- Test token expiration
```

**Testing Tools:**
```
Unit:         testing (stdlib), testify/assert, testify/mock
Integration:  testcontainers-go (Docker-based tests)
E2E:          httptest (stdlib), testify/suite
Coverage:     go test -coverprofile=coverage.out
CI/CD:        GitHub Actions, GitLab CI
```

**Implementation Priority:** 🔴 Critical (Weeks 2-4)

**Estimated Effort:** 3-4 weeks (parallel with other work)

---

### 🟡 Priority 1 (High - Address Within Month)

#### 4. Basic Health Check Endpoint

**Current State:**
```go
r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
    fmt.Fprintf(w, `{"status":"healthy","service":"auth-service","version":"2.0.0"}`)
})
```

**Problems:**
- ❌ Doesn't check database connectivity
- ❌ Doesn't check Redis connectivity
- ❌ Doesn't check RabbitMQ connectivity
- ❌ Can return "healthy" when service is unusable

**Recommendation:**
Implement comprehensive health checks:

```go
GET /health
Response: 200 OK (all healthy)
{
  "status": "healthy",
  "service": "auth-service",
  "version": "2.0.0",
  "timestamp": "2025-01-15T10:30:00Z",
  "checks": {
    "database": {
      "status": "healthy",
      "latency_ms": 2.3
    },
    "redis": {
      "status": "healthy",
      "latency_ms": 0.8
    },
    "rabbitmq": {
      "status": "healthy",
      "latency_ms": 1.2
    }
  }
}

Response: 503 Service Unavailable (degraded)
{
  "status": "degraded",
  "service": "auth-service",
  "version": "2.0.0",
  "timestamp": "2025-01-15T10:30:00Z",
  "checks": {
    "database": {
      "status": "healthy",
      "latency_ms": 2.1
    },
    "redis": {
      "status": "unhealthy",
      "error": "connection timeout",
      "latency_ms": 5000
    },
    "rabbitmq": {
      "status": "healthy",
      "latency_ms": 1.5
    }
  }
}
```

**Additional Endpoints:**
```
GET /health/liveness  → Simple check (process alive)
GET /health/readiness → Dependency check (ready to serve traffic)
```

**Kubernetes Integration:**
```yaml
livenessProbe:
  httpGet:
    path: /health/liveness
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/readiness
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

**Implementation Priority:** 🟡 High (Week 2)

**Estimated Effort:** 1 day

**Files to Create:**
- `internal/app/handler/v1/health_handler.go`

---

#### 5. Missing Observability (Metrics & Tracing)

**Current State:**
- ❌ No Prometheus metrics
- ❌ No distributed tracing
- ❌ No performance monitoring
- ❌ No alerting

**Impact:**
- Cannot measure performance
- Cannot detect anomalies
- Cannot debug production issues
- No SLA tracking

**Recommendation:**

**Phase 1: Prometheus Metrics**

Key metrics to track:
```
Business Metrics:
- auth_registrations_total{method="email|phone"}
- auth_login_attempts_total{method="password|otp", status="success|failure"}
- auth_login_failures_by_reason{reason="invalid_password|account_locked|2fa_failed"}
- auth_2fa_enrollments_total
- auth_2fa_verifications_total{status="success|failure"}
- auth_password_resets_total
- auth_active_sessions_gauge
- auth_token_refreshes_total

Technical Metrics:
- http_requests_total{endpoint, method, status}
- http_request_duration_seconds{endpoint, method}
- database_query_duration_seconds{operation}
- redis_operation_duration_seconds{operation}
- outbox_processing_duration_seconds
- outbox_pending_events_gauge
- outbox_publish_failures_total

Security Metrics:
- auth_account_lockouts_total{reason}
- auth_suspicious_login_attempts_total{reason}
- auth_rate_limit_exceeded_total{endpoint}
```

**Implementation:**
```go
// internal/metrics/metrics.go
import "github.com/prometheus/client_golang/prometheus"

var (
    LoginAttempts = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "auth_login_attempts_total",
            Help: "Total number of login attempts",
        },
        []string{"method", "status"},
    )

    HTTPDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "http_request_duration_seconds",
            Help: "HTTP request duration",
            Buckets: prometheus.DefBuckets,
        },
        []string{"endpoint", "method"},
    )
)

func init() {
    prometheus.MustRegister(LoginAttempts)
    prometheus.MustRegister(HTTPDuration)
}
```

**Expose Metrics:**
```go
r.Handle("/metrics", promhttp.Handler())
```

**Phase 2: Distributed Tracing (OpenTelemetry)**

```
Trace:
- Request ID propagation (already implemented ✅)
- Database query tracing
- Redis operation tracing
- External service call tracing (email, SMS)
- Outbox relay tracing

Backend Options:
- Jaeger (recommended for start)
- Tempo (Grafana Labs)
- AWS X-Ray
- Datadog APM
```

**Phase 3: Alerting**

**Prometheus Alertmanager Rules:**
```yaml
groups:
  - name: auth_service
    rules:
      - alert: HighLoginFailureRate
        expr: rate(auth_login_attempts_total{status="failure"}[5m]) > 10
        for: 5m
        annotations:
          summary: "High login failure rate detected"

      - alert: DatabaseConnectionFailure
        expr: up{job="auth-service"} == 0
        for: 1m
        annotations:
          summary: "Auth service database connection failed"

      - alert: OutboxBacklog
        expr: outbox_pending_events_gauge > 1000
        for: 10m
        annotations:
          summary: "Email outbox has large backlog"
```

**Implementation Priority:** 🟡 High (Weeks 3-4)

**Estimated Effort:** 1 week

---

#### 6. Missing User Management Endpoints

**Current State:**
- ✅ Service methods implemented
- ❌ Not exposed via HTTP

**Missing Endpoints:**
```
PUT /api/v1/users/:id (admin only)
- Update user profile
- Update roles
- Update metadata

POST /api/v1/users/:id/deactivate (admin only)
- Deactivate user account

POST /api/v1/users/:id/reactivate (admin only)
- Reactivate user account

DELETE /api/v1/users/:id (admin only)
- Soft delete user

GET /api/v1/users (admin only)
- List users with pagination, filtering

GET /api/v1/users/:id/sessions (user or admin)
- List active sessions

DELETE /api/v1/users/:id/sessions/:session_id (user or admin)
- Revoke specific session

POST /api/v1/users/:id/unlock (admin only)
- Manually unlock locked account
```

**Implementation Priority:** 🟡 Medium (Week 4)

**Estimated Effort:** 2-3 days

**Security Consideration:**
- Require admin role for user management
- Add RBAC middleware (`middleware/rbac.go`)
- Audit log all admin actions

---

### 🟢 Priority 2 (Medium - Address Within Quarter)

#### 7. Advanced Security Features

**Current Gaps:**
- No anomaly detection
- No device fingerprinting
- No geo-location tracking
- No risk-based authentication
- No CAPTCHA on signup/login

**Recommendations:**

**7a. Anomaly Detection**

Detect suspicious behavior:
```
- Login from new country/city
- Login from new device
- Login at unusual time
- Multiple IPs for same user
- Rapid account creation (same IP)
- Password spray attacks
```

**Implementation:**
```go
// internal/service/anomaly_detector.go

type AnomalyDetector struct {
    repo  AnomalyRepository
    redis RedisRepository
}

func (d *AnomalyDetector) CheckLogin(userID, ip, userAgent, country string) (RiskLevel, []string) {
    var anomalies []string

    // Check if new country
    lastCountry := d.redis.GetLastCountry(userID)
    if lastCountry != "" && lastCountry != country {
        anomalies = append(anomalies, "new_country")
    }

    // Check if new device
    isKnownDevice := d.repo.IsKnownDevice(userID, fingerprintDevice(userAgent))
    if !isKnownDevice {
        anomalies = append(anomalies, "new_device")
    }

    // Check time-based anomaly
    if d.isUnusualTime(userID) {
        anomalies = append(anomalies, "unusual_time")
    }

    // Calculate risk level
    risk := d.calculateRiskLevel(anomalies)
    return risk, anomalies
}

type RiskLevel string
const (
    RiskLow    RiskLevel = "low"
    RiskMedium RiskLevel = "medium"
    RiskHigh   RiskLevel = "high"
)
```

**Risk-Based Actions:**
- **Low Risk:** Allow login
- **Medium Risk:** Require email OTP verification
- **High Risk:** Require 2FA + email verification + CAPTCHA

**Database Schema Addition:**
```sql
CREATE TABLE user_login_history (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    ip_address INET,
    country VARCHAR(100),
    city VARCHAR(100),
    device_fingerprint VARCHAR(255),
    risk_level VARCHAR(20),
    anomalies JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_login_history_user_id ON user_login_history(user_id);
CREATE INDEX idx_login_history_created_at ON user_login_history(created_at DESC);
```

**7b. Device Fingerprinting**

Generate unique device ID from:
- User-Agent
- Screen resolution
- Timezone
- Language
- Platform
- Browser plugins

**Library:** `github.com/fingerprintjs/fingerprintjs-pro` (client-side)

**Server-side storage:**
```sql
CREATE TABLE trusted_devices (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    device_fingerprint VARCHAR(255) UNIQUE,
    device_name VARCHAR(100),
    trusted_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ
);
```

**7c. Geo-Location Tracking**

**IP to Location Service:**
- **MaxMind GeoLite2** (free, local database)
- **ipapi.co** (API-based)
- **ipstack.com** (API-based)

**Implementation:**
```go
// internal/utils/geolocation.go
import "github.com/oschwald/geoip2-golang"

type GeoLocator struct {
    db *geoip2.Reader
}

func (g *GeoLocator) GetLocation(ip string) (*Location, error) {
    record, err := g.db.City(net.ParseIP(ip))
    if err != nil {
        return nil, err
    }

    return &Location{
        Country: record.Country.Names["en"],
        City:    record.City.Names["en"],
        Lat:     record.Location.Latitude,
        Lon:     record.Location.Longitude,
    }, nil
}
```

**7d. CAPTCHA Integration**

**Trigger CAPTCHA on:**
- 3rd failed login attempt
- Account creation (optional)
- Password reset request
- High-risk logins

**Options:**
- **Google reCAPTCHA v3** (invisible, score-based)
- **hCaptcha** (privacy-focused)
- **Cloudflare Turnstile** (free, privacy-focused)

**Recommendation:** hCaptcha or Cloudflare Turnstile

**Implementation:**
```go
// internal/client/captcha/client.go

type CaptchaClient interface {
    Verify(token string, remoteIP string) (bool, error)
}

type HCaptchaClient struct {
    secret string
    client *http.Client
}

func (c *HCaptchaClient) Verify(token, remoteIP string) (bool, error) {
    // Call hCaptcha verification API
    // Return true if valid, false otherwise
}
```

**Configuration:**
```yaml
captcha:
  provider: "hcaptcha"  # hcaptcha, recaptcha, turnstile
  site_key: "your-site-key"
  secret_key: "your-secret-key"
  enabled: true
  threshold: 0.5  # for reCAPTCHA v3
```

**Implementation Priority:** 🟢 Medium (Weeks 6-8)

**Estimated Effort:** 2-3 weeks

---

#### 8. Missing Audit Log Query Endpoint

**Current State:**
- ✅ Audit logs written to database
- ❌ No way to query/view audit logs

**Recommendation:**

```go
GET /api/v1/admin/audit-logs (admin only)
Query params:
  - user_id (filter by user)
  - event_type (filter by event)
  - start_date (ISO 8601)
  - end_date (ISO 8601)
  - page (pagination)
  - limit (page size, max 100)

Response: 200 OK
{
  "logs": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "event_type": "login_success",
      "event_data": {
        "method": "password",
        "ip": "192.168.1.1"
      },
      "ip_address": "192.168.1.1",
      "user_agent": "...",
      "created_at": "2025-01-15T10:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 1234
  }
}
```

**Implementation Priority:** 🟢 Low (Week 5)

**Estimated Effort:** 1 day

---

## Enhancement Recommendations

### 1. API Versioning Strategy

**Current State:**
- Single API version (`/api/v1`)
- No versioning strategy documented

**Recommendation:**

**URL Path Versioning** (current approach) ✅
```
/api/v1/auth/login
/api/v2/auth/login (future)
```

**Version Deprecation Policy:**
```
v1.0 → v1.1 → v2.0
     ↓        ↓
   6 months  12 months
   notice    support
```

**Breaking Change Policy:**
- Minor version changes: Backward compatible
- Major version changes: May break compatibility
- Maintain n-1 versions (e.g., v2 live, v1 deprecated but supported)

**Implementation:**
```go
// internal/app/handler/v1/...  (existing)
// internal/app/handler/v2/...  (future)

r.Route("/api/v1", func(r chi.Router) {
    v1.RegisterRoutes(r)
})

r.Route("/api/v2", func(r chi.Router) {
    v2.RegisterRoutes(r)
})
```

---

### 2. Enhanced Error Handling

**Current State:**
- Basic error responses
- No standardized error codes

**Recommendation:**

**Standardized Error Response:**
```go
type ErrorResponse struct {
    Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
    Code      string            `json:"code"`       // AUTH001, AUTH002, etc.
    Message   string            `json:"message"`    // Human-readable message
    Details   map[string]string `json:"details,omitempty"` // Field-level errors
    RequestID string            `json:"request_id"` // For debugging
    Timestamp time.Time         `json:"timestamp"`
}
```

**Example Error Codes:**
```
AUTH001: Invalid credentials
AUTH002: Account locked
AUTH003: Email not verified
AUTH004: 2FA required
AUTH005: Invalid token
AUTH006: Token expired
AUTH007: Rate limit exceeded
AUTH008: Password does not meet requirements
AUTH009: Email already exists
AUTH010: OTP invalid or expired
```

**Implementation:**
```go
// internal/app/model/api/error.go

var ErrorCodes = map[string]ErrorCode{
    "invalid_credentials": {
        Code:       "AUTH001",
        Message:    "Invalid email or password",
        HTTPStatus: http.StatusUnauthorized,
    },
    "account_locked": {
        Code:       "AUTH002",
        Message:    "Account is locked due to multiple failed login attempts",
        HTTPStatus: http.StatusForbidden,
    },
    // ...
}
```

**Benefits:**
- Client can programmatically handle errors
- Better debugging with request IDs
- Consistent error format across all endpoints
- Easier to document in Swagger

---

### 3. Request/Response Pagination

**Current State:**
- No pagination implemented for list endpoints

**Recommendation:**

**Cursor-Based Pagination** (recommended for large datasets):
```go
GET /api/v1/users?limit=50&cursor=eyJpZCI6IjEyMyJ9

Response:
{
  "data": [...],
  "pagination": {
    "next_cursor": "eyJpZCI6IjE3MyJ9",
    "has_more": true,
    "limit": 50
  }
}
```

**Benefits:**
- Efficient for large datasets
- Consistent results (no duplicate/missing items)
- Works with real-time data

**Offset-Based Pagination** (simpler, good for small datasets):
```go
GET /api/v1/users?page=2&limit=50

Response:
{
  "data": [...],
  "pagination": {
    "page": 2,
    "limit": 50,
    "total": 1234,
    "total_pages": 25
  }
}
```

---

### 4. Request Validation Enhancement

**Current State:**
- Basic validation using struct tags

**Recommendation:**

**Comprehensive Validation Library:**
```go
import "github.com/go-playground/validator/v10"

type SignupRequest struct {
    Email    string `json:"email" validate:"required,email"`
    Name     string `json:"name" validate:"required,min=2,max=100"`
    Password string `json:"password" validate:"required,min=8,password_strength"`
}

// Custom validation
func ValidatePasswordStrength(fl validator.FieldLevel) bool {
    password := fl.Field().String()
    return utils.ValidatePassword(password, config.PasswordPolicy{...})
}
```

**Custom Validators:**
- `password_strength` - Check complexity
- `phone` - International phone number format
- `no_sql_injection` - Basic SQL injection prevention
- `no_xss` - Basic XSS prevention

---

### 5. Caching Strategy

**Current State:**
- Redis used for temporary state (OTP, sessions)
- No response caching
- No query result caching

**Recommendation:**

**Cache Layers:**

**1. Application-Level Cache (Redis)**
```
Cache user profile (5 min TTL)
Cache user permissions (10 min TTL)
Cache public key for JWT verification (1 hour TTL)
```

**2. Database Query Cache**
```
Frequently accessed queries:
- Get user by email
- Check if email exists
- Get user roles and permissions
```

**Implementation:**
```go
// internal/app/repo/user_repository.go

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
    cacheKey := fmt.Sprintf("user:email:%s", email)

    // Try cache first
    cached, err := r.redis.Get(ctx, cacheKey)
    if err == nil {
        var user User
        json.Unmarshal([]byte(cached), &user)
        return &user, nil
    }

    // Cache miss, query database
    user, err := r.db.GetUserByEmail(email)
    if err != nil {
        return nil, err
    }

    // Store in cache
    data, _ := json.Marshal(user)
    r.redis.Set(ctx, cacheKey, data, 5*time.Minute)

    return user, nil
}
```

**Cache Invalidation:**
```
On user update: Invalidate user cache
On role change: Invalidate permission cache
On password change: Invalidate all user sessions
```

---

### 6. Background Job System

**Current State:**
- Only outbox relay worker
- No other background jobs

**Recommendation:**

**Use Case for Background Jobs:**
1. **Session cleanup** - Delete expired sessions
2. **Token cleanup** - Delete expired refresh tokens, password reset tokens
3. **Audit log archival** - Move old audit logs to cold storage
4. **Email digest** - Send weekly security reports
5. **Metrics aggregation** - Pre-calculate metrics for dashboards
6. **Account deletion** - Permanent deletion of soft-deleted accounts after retention period

**Technology Options:**

**Option 1: Simple Cron Worker (Current Pattern)**
```go
// internal/worker/cleanup_worker.go

type CleanupWorker struct {
    repo   CleanupRepository
    logger *logrus.Logger
}

func (w *CleanupWorker) Run(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            w.cleanupExpiredSessions()
            w.cleanupExpiredTokens()
        case <-ctx.Done():
            return
        }
    }
}
```

**Option 2: Distributed Job Queue (Advanced)**
- **Asynq** (Redis-based, Go-native) ✅ Recommended
- **RabbitMQ** (already using for events)
- **Temporal** (complex workflows)

**Asynq Example:**
```go
import "github.com/hibiken/asynq"

// Enqueue job
client := asynq.NewClient(asynq.RedisClientOpt{Addr: "localhost:6379"})
task := asynq.NewTask("session:cleanup", nil)
client.Enqueue(task, asynq.Queue("cleanup"))

// Worker
server := asynq.NewServer(
    asynq.RedisClientOpt{Addr: "localhost:6379"},
    asynq.Config{Concurrency: 10},
)

server.HandleFunc("session:cleanup", handleSessionCleanup)
server.Run()
```

**Implementation Priority:** 🟢 Medium (Week 6)

**Estimated Effort:** 1 week

---

## New Feature Proposals

### 1. OAuth2/OIDC Provider Capabilities

**Overview:**
Transform auth service into a full OAuth2 Authorization Server and OpenID Connect (OIDC) Identity Provider.

**Use Case:**
- Allow third-party apps to authenticate users via "Sign in with [Your Platform]"
- SSO (Single Sign-On) across multiple internal applications
- API authorization with OAuth2 scopes

**OAuth2 Flows to Support:**

1. **Authorization Code Flow** (most secure, for web apps)
2. **PKCE Extension** (for mobile/SPA apps)
3. **Client Credentials Flow** (for service-to-service)
4. **Refresh Token Flow** (already implemented ✅)

**New Endpoints Required:**

```
# OAuth2 Endpoints
GET  /oauth2/authorize          # Authorization endpoint
POST /oauth2/token              # Token endpoint
POST /oauth2/revoke             # Token revocation
POST /oauth2/introspect         # Token introspection
GET  /oauth2/.well-known/openid-configuration  # Discovery

# OIDC Endpoints
GET  /oauth2/userinfo           # User info endpoint
GET  /oauth2/jwks               # JSON Web Key Set (already have public key)

# Client Management
POST   /api/v1/oauth2/clients   # Register OAuth2 client
GET    /api/v1/oauth2/clients   # List clients
PUT    /api/v1/oauth2/clients/:id
DELETE /api/v1/oauth2/clients/:id
```

**New Database Tables:**

```sql
-- OAuth2 Clients (applications that can authenticate)
CREATE TABLE oauth2_clients (
    id UUID PRIMARY KEY,
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret_hash VARCHAR(255),  -- bcrypt hashed
    client_name VARCHAR(255) NOT NULL,
    client_type VARCHAR(50) NOT NULL,  -- confidential, public
    redirect_uris JSONB NOT NULL,      -- allowed redirect URIs
    allowed_scopes JSONB NOT NULL,     -- ["openid", "profile", "email"]
    allowed_grant_types JSONB NOT NULL, -- ["authorization_code", "refresh_token"]
    logo_uri TEXT,
    terms_of_service_uri TEXT,
    policy_uri TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Authorization Codes (short-lived, exchanged for tokens)
CREATE TABLE oauth2_authorization_codes (
    id UUID PRIMARY KEY,
    code VARCHAR(255) UNIQUE NOT NULL,
    client_id UUID REFERENCES oauth2_clients(id),
    user_id UUID REFERENCES users(id),
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge VARCHAR(255),       -- PKCE
    code_challenge_method VARCHAR(10), -- S256 or plain
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- OAuth2 Access Tokens (can coexist with JWT tokens)
CREATE TABLE oauth2_access_tokens (
    id UUID PRIMARY KEY,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    client_id UUID REFERENCES oauth2_clients(id),
    user_id UUID REFERENCES users(id),
    scope TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- User Consent (remember user approval for specific clients)
CREATE TABLE oauth2_user_consents (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    client_id UUID REFERENCES oauth2_clients(id),
    scopes JSONB NOT NULL,
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, client_id)
);
```

**OAuth2 Scopes:**
```
openid          - OIDC required scope
profile         - User's full name, profile picture
email           - User's email address
phone           - User's phone number
address         - User's address
offline_access  - Request refresh token
roles           - User's roles (custom scope)
```

**Implementation Libraries:**
- **fosite** - Go OAuth2 & OIDC framework (comprehensive)
- **ory/hydra** - Production-ready OAuth2 server (can study architecture)
- **Custom implementation** (full control)

**Authorization Flow Example:**

```
1. Client redirects user to:
   GET /oauth2/authorize?
     response_type=code&
     client_id=abc123&
     redirect_uri=https://client.com/callback&
     scope=openid+profile+email&
     state=random_state

2. User logs in (if not authenticated)

3. User sees consent screen:
   "App X wants to access your profile and email"
   [Allow] [Deny]

4. If allowed, redirect to client:
   https://client.com/callback?code=AUTH_CODE&state=random_state

5. Client exchanges code for token:
   POST /oauth2/token
   {
     "grant_type": "authorization_code",
     "code": "AUTH_CODE",
     "redirect_uri": "https://client.com/callback",
     "client_id": "abc123",
     "client_secret": "secret"
   }

6. Response:
   {
     "access_token": "...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "...",
     "id_token": "..." // JWT with user info (OIDC)
   }
```

**Benefits:**
- **Single Sign-On** across multiple apps
- **Third-party integration** (allow others to build on your platform)
- **Standard protocol** (OAuth2 is industry standard)
- **Granular permissions** (scope-based access)

**Implementation Priority:** 🟢 P2 (Quarter 2)

**Estimated Effort:** 4-6 weeks

---

### 2. WebAuthn/Passkeys Support

**Overview:**
Implement passwordless authentication using FIDO2/WebAuthn standard (biometrics, security keys).

**What are Passkeys?**
- Modern replacement for passwords
- Use device biometrics (Face ID, Touch ID, Windows Hello)
- Phishing-resistant (public key cryptography)
- Synced across devices (Apple/Google/Microsoft)

**Use Cases:**
- **Primary authentication** (replace password entirely)
- **Step-up authentication** (for sensitive operations)
- **2FA alternative** (more secure than TOTP)

**New Endpoints:**

```
# Registration
POST /api/v1/auth/webauthn/register/begin
POST /api/v1/auth/webauthn/register/finish

# Authentication
POST /api/v1/auth/webauthn/login/begin
POST /api/v1/auth/webauthn/login/finish

# Management
GET    /api/v1/auth/webauthn/credentials     # List user's credentials
DELETE /api/v1/auth/webauthn/credentials/:id # Remove credential
```

**New Database Tables:**

```sql
CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    credential_id BYTEA UNIQUE NOT NULL,  -- Public key credential ID
    public_key BYTEA NOT NULL,             -- User's public key
    aaguid UUID NOT NULL,                  -- Authenticator AAGUID
    sign_count INTEGER NOT NULL DEFAULT 0, -- Counter (replay protection)
    transports JSONB,                      -- ["usb", "nfc", "ble", "internal"]
    backup_eligible BOOLEAN DEFAULT FALSE, -- Can be backed up (passkey)
    backup_state BOOLEAN DEFAULT FALSE,    -- Is backed up
    credential_name VARCHAR(100),          -- User-friendly name
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_webauthn_user_id ON webauthn_credentials(user_id);
CREATE INDEX idx_webauthn_credential_id ON webauthn_credentials(credential_id);
```

**Implementation Library:**
```go
import "github.com/go-webauthn/webauthn/webauthn"

web, err := webauthn.New(&webauthn.Config{
    RPDisplayName: "Your Auth Service",
    RPID:          "yourdomain.com",
    RPOrigins:     []string{"https://yourdomain.com"},
})
```

**Registration Flow:**

```javascript
// Frontend (JavaScript)
const credential = await navigator.credentials.create({
    publicKey: {
        challenge: challengeFromServer,
        rp: { name: "Your Auth Service", id: "yourdomain.com" },
        user: {
            id: userIdFromServer,
            name: "user@example.com",
            displayName: "John Doe"
        },
        pubKeyCredParams: [
            { type: "public-key", alg: -7 },  // ES256
            { type: "public-key", alg: -257 } // RS256
        ],
        authenticatorSelection: {
            authenticatorAttachment: "platform", // or "cross-platform"
            residentKey: "required",
            userVerification: "required"
        }
    }
});

// Send credential to server
await fetch('/api/v1/auth/webauthn/register/finish', {
    method: 'POST',
    body: JSON.stringify(credential)
});
```

**Authentication Flow:**

```javascript
// Frontend
const assertion = await navigator.credentials.get({
    publicKey: {
        challenge: challengeFromServer,
        rpId: "yourdomain.com",
        userVerification: "required"
    }
});

// Send assertion to server
const response = await fetch('/api/v1/auth/webauthn/login/finish', {
    method: 'POST',
    body: JSON.stringify(assertion)
});

// Receive JWT tokens
const { access_token, refresh_token } = await response.json();
```

**Security Considerations:**
- ✅ Phishing-resistant (origin-bound)
- ✅ No password to leak
- ✅ Biometric never leaves device
- ✅ Replay attack protection (sign counter)
- ⚠️ Requires HTTPS
- ⚠️ Browser compatibility (90%+ modern browsers)

**Browser Support:**
- ✅ Chrome/Edge (2019+)
- ✅ Safari (2020+)
- ✅ Firefox (2019+)
- ✅ Mobile browsers (iOS 14+, Android 9+)

**Implementation Priority:** 🟢 P2 (Quarter 2-3)

**Estimated Effort:** 3-4 weeks

**Benefits:**
- **Best user experience** (one tap login)
- **Highest security** (no password attacks)
- **Future-proof** (industry moving toward passkeys)

---

### 3. Magic Link Authentication

**Overview:**
Passwordless authentication via email link (no OTP codes to type).

**Flow:**

```
1. User enters email
2. System sends email with unique link
3. User clicks link
4. System validates link and logs in user
5. Redirect to application
```

**New Endpoints:**

```
POST /api/v1/auth/magic-link/request
Request:
{
  "email": "user@example.com",
  "redirect_uri": "https://yourapp.com/dashboard" (optional)
}

Response: 200 OK
{
  "message": "Magic link sent to your email"
}

GET /api/v1/auth/magic-link/verify?token=MAGIC_TOKEN
Response: 302 Redirect
Location: https://yourapp.com/dashboard?access_token=JWT&refresh_token=REFRESH
```

**New Database Table:**

```sql
CREATE TABLE magic_link_tokens (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    redirect_uri TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_magic_link_token_hash ON magic_link_tokens(token_hash) WHERE used_at IS NULL;
CREATE INDEX idx_magic_link_expires_at ON magic_link_tokens(expires_at);
```

**Email Template:**

```html
Subject: Your login link for [App Name]

Hello {{ .Name }},

Click the link below to securely sign in to your account:

{{ .MagicLinkURL }}

This link will expire in 15 minutes.

If you didn't request this login link, you can safely ignore this email.

---
Sent by [App Name]
```

**Security Considerations:**

1. **Short expiration** (15 minutes)
2. **One-time use** (mark as used after click)
3. **Unique token** (cryptographically random, 32+ bytes)
4. **Rate limiting** (3 links per hour per email)
5. **Optional IP binding** (link only works from same IP)

**Implementation:**

```go
func (s *AuthService) RequestMagicLink(ctx context.Context, email, redirectURI string) error {
    user, err := s.userRepo.GetUserByEmail(ctx, email)
    if err != nil {
        // Don't reveal if user exists (security)
        return nil
    }

    // Generate secure token
    token := generateSecureToken(32) // 256 bits
    tokenHash := sha256Hash(token)

    // Store in database
    magicLink := &MagicLinkToken{
        UserID:      user.ID,
        TokenHash:   tokenHash,
        RedirectURI: redirectURI,
        ExpiresAt:   time.Now().Add(15 * time.Minute),
        IPAddress:   getIPFromContext(ctx),
        UserAgent:   getUserAgentFromContext(ctx),
    }
    err = s.magicLinkRepo.Create(ctx, magicLink)

    // Send email (via outbox)
    linkURL := fmt.Sprintf("%s/api/v1/auth/magic-link/verify?token=%s",
        s.config.BaseURL, token)

    s.emailPublisher.Publish(ctx, "magic_link", email, map[string]string{
        "name": user.Name,
        "magic_link_url": linkURL,
    })

    return nil
}
```

**Implementation Priority:** 🟢 P2 (Quarter 2)

**Estimated Effort:** 1 week

---

### 4. Social Login (OAuth2 Client - Google, GitHub, etc.)

**Overview:**
Allow users to sign in with existing accounts (Google, GitHub, Facebook, Apple).

**Supported Providers:**

| Provider | User Base | Best For |
|----------|-----------|----------|
| **Google** | 3B+ users | General consumer apps |
| **GitHub** | 100M+ developers | Developer tools, B2B |
| **Apple** | 2B+ users | iOS/Mac apps |
| **Facebook** | 3B+ users | Social apps |
| **Microsoft** | 400M+ users | Enterprise apps |
| **LinkedIn** | 900M+ users | Professional apps |

**New Endpoints:**

```
# Initiate OAuth flow
GET /api/v1/auth/social/:provider/login
  ?redirect_uri=https://yourapp.com/dashboard

# OAuth callback
GET /api/v1/auth/social/:provider/callback
  ?code=OAUTH_CODE&state=STATE

# Link social account to existing user
POST /api/v1/auth/social/:provider/link (authenticated)

# Unlink social account
DELETE /api/v1/auth/social/:provider/unlink (authenticated)
```

**New Database Tables:**

```sql
CREATE TABLE social_accounts (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    provider VARCHAR(50) NOT NULL,     -- google, github, facebook
    provider_user_id VARCHAR(255) NOT NULL,  -- User ID from provider
    provider_email VARCHAR(255),
    provider_name VARCHAR(255),
    provider_avatar_url TEXT,
    access_token_encrypted TEXT,       -- Encrypted OAuth access token
    refresh_token_encrypted TEXT,      -- Encrypted OAuth refresh token
    expires_at TIMESTAMPTZ,
    raw_user_data JSONB,               -- Full user profile from provider
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_social_accounts_user_id ON social_accounts(user_id);
CREATE INDEX idx_social_accounts_provider ON social_accounts(provider, provider_user_id);
```

**Configuration:**

```yaml
social:
  google:
    enabled: true
    client_id: "your-google-client-id"
    client_secret: "your-google-client-secret"
    scopes: ["openid", "profile", "email"]

  github:
    enabled: true
    client_id: "your-github-client-id"
    client_secret: "your-github-client-secret"
    scopes: ["user:email"]

  apple:
    enabled: true
    client_id: "your-apple-client-id"
    team_id: "your-apple-team-id"
    key_id: "your-apple-key-id"
    private_key_path: "./assets/apple_private_key.p8"
    scopes: ["name", "email"]
```

**Implementation Library:**

```go
import "golang.org/x/oauth2"
import "golang.org/x/oauth2/google"
import "golang.org/x/oauth2/github"

var googleOAuthConfig = &oauth2.Config{
    ClientID:     cfg.Social.Google.ClientID,
    ClientSecret: cfg.Social.Google.ClientSecret,
    RedirectURL:  "https://yourdomain.com/api/v1/auth/social/google/callback",
    Scopes:       []string{"openid", "profile", "email"},
    Endpoint:     google.Endpoint,
}
```

**Google Login Flow:**

```go
func (h *AuthHandler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
    state := generateRandomState() // CSRF protection
    h.redis.Set(ctx, "oauth_state:"+state, "pending", 10*time.Minute)

    url := googleOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
    // Verify state (CSRF protection)
    state := r.URL.Query().Get("state")
    // ... validate state ...

    // Exchange code for token
    code := r.URL.Query().Get("code")
    token, err := googleOAuthConfig.Exchange(ctx, code)

    // Fetch user info from Google
    client := googleOAuthConfig.Client(ctx, token)
    resp, _ := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
    var googleUser GoogleUserInfo
    json.NewDecoder(resp.Body).Decode(&googleUser)

    // Find or create user in database
    user, err := h.service.FindOrCreateSocialUser(ctx, "google", googleUser)

    // Generate JWT tokens
    accessToken, refreshToken := h.jwtManager.GenerateTokens(user)

    // Redirect to app with tokens
    redirectURI := fmt.Sprintf("%s?access_token=%s&refresh_token=%s",
        r.URL.Query().Get("redirect_uri"), accessToken, refreshToken)
    http.Redirect(w, r, redirectURI, http.StatusTemporaryRedirect)
}
```

**Account Linking Strategy:**

**Option 1: Email-based linking (automatic)**
- If user logs in with Google (email: user@example.com)
- And existing user has same email → Auto-link accounts

**Option 2: Manual linking**
- User must explicitly link social account in settings
- More secure but less convenient

**Recommendation:** Use Option 1 with email verification requirement

**Security Considerations:**

1. **CSRF Protection:** Use state parameter
2. **Secure token storage:** Encrypt OAuth tokens in database
3. **Token refresh:** Implement refresh for long-lived access
4. **Email verification:** Only auto-link if email is verified by provider
5. **Provider validation:** Verify OAuth callback origin

**Implementation Priority:** 🟢 P2 (Quarter 2)

**Estimated Effort:** 2-3 weeks

---

### 5. Multi-Tenancy Enhancements

**Current State:**
- Single-tenant architecture
- User metadata can store tenant info (JSONB)

**Proposed Enhancement:**
Full multi-tenancy support with tenant isolation.

**Use Cases:**
- SaaS platform serving multiple organizations
- Each tenant has isolated users, roles, data
- Cross-tenant user access (optional)

**Architecture Options:**

**Option 1: Schema-per-Tenant** (highest isolation)
```sql
-- Create schema for each tenant
CREATE SCHEMA tenant_abc123;
CREATE SCHEMA tenant_xyz789;

-- Each tenant gets own tables
CREATE TABLE tenant_abc123.users (...);
CREATE TABLE tenant_xyz789.users (...);
```

**Pros:**
- ✅ Strong data isolation
- ✅ Easy to backup individual tenants
- ✅ Can scale by moving schemas to different databases

**Cons:**
- ❌ Schema proliferation
- ❌ Complex migrations (run on all schemas)
- ❌ Not practical for 1000+ tenants

**Option 2: Row-Level Tenancy** (shared tables, tenant_id column) ✅ **Recommended**

```sql
-- All tables have tenant_id
CREATE TABLE users (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    email TEXT NOT NULL,
    -- ...
    UNIQUE(tenant_id, email)  -- Email unique per tenant
);

-- PostgreSQL Row-Level Security (RLS)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);
```

**Pros:**
- ✅ Simple to implement
- ✅ Easy migrations
- ✅ Efficient for large number of tenants
- ✅ PostgreSQL RLS provides automatic isolation

**Cons:**
- ⚠️ Risk of tenant data leakage (must be careful)
- ⚠️ All tenants share same database resources

**Option 3: Database-per-Tenant** (highest isolation, highest cost)
- Each tenant gets entire separate database
- Good for enterprise customers with compliance requirements

**Recommendation:** Use **Option 2 (Row-Level Tenancy with RLS)**

**New Database Tables:**

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,  -- subdomain or identifier
    domain VARCHAR(255) UNIQUE,         -- Custom domain (optional)
    plan VARCHAR(50) NOT NULL,          -- free, pro, enterprise
    status VARCHAR(50) NOT NULL,        -- active, suspended, trial
    settings JSONB DEFAULT '{}',
    max_users INTEGER,
    max_api_calls INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE tenant_users (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    user_id UUID NOT NULL REFERENCES users(id),
    role VARCHAR(50) NOT NULL,          -- tenant-specific role
    status VARCHAR(50) NOT NULL,        -- active, invited, suspended
    invited_by UUID REFERENCES users(id),
    invited_at TIMESTAMPTZ,
    joined_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, user_id)
);

CREATE INDEX idx_tenant_users_tenant_id ON tenant_users(tenant_id);
CREATE INDEX idx_tenant_users_user_id ON tenant_users(user_id);
```

**Tenant Context Middleware:**

```go
// internal/app/middleware/tenant.go

func TenantContext(tenantRepo repo.TenantRepository) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract tenant from:
            // 1. Subdomain (tenant1.yourapp.com)
            // 2. Custom domain (customer.com)
            // 3. Header (X-Tenant-ID)
            // 4. Query param (tenant_id)

            host := r.Host
            tenantSlug := extractSubdomain(host)

            tenant, err := tenantRepo.GetTenantBySlug(r.Context(), tenantSlug)
            if err != nil {
                http.Error(w, "Tenant not found", http.StatusNotFound)
                return
            }

            // Add tenant to context
            ctx := context.WithValue(r.Context(), "tenant_id", tenant.ID)

            // Set PostgreSQL RLS variable
            db.Exec("SET LOCAL app.current_tenant_id = ?", tenant.ID)

            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

**JWT Claims with Tenant:**

```go
type JWTClaims struct {
    jwt.RegisteredClaims
    UserID   uuid.UUID   `json:"user_id"`
    Email    string      `json:"email"`
    TenantID uuid.UUID   `json:"tenant_id"`  // Add tenant ID
    Roles    []string    `json:"roles"`
}
```

**Tenant Isolation Checklist:**
- ✅ All queries filtered by tenant_id
- ✅ PostgreSQL RLS policies enforced
- ✅ JWT tokens include tenant_id
- ✅ Cross-tenant API calls blocked
- ✅ Audit logs include tenant_id
- ✅ Background jobs process per tenant

**Implementation Priority:** 🟢 P2 (Quarter 3)

**Estimated Effort:** 4-6 weeks

---

### 6. Email Change Flow

**Current State:**
- ❌ No email change functionality

**Use Case:**
- User wants to change email address
- Must verify new email before change is applied

**New Endpoints:**

```
POST /api/v1/auth/email/change-request (authenticated)
Request:
{
  "new_email": "newemail@example.com",
  "password": "current_password" // For security
}
Response: 200 OK
{
  "message": "Verification email sent to newemail@example.com"
}

POST /api/v1/auth/email/change-verify
Request:
{
  "token": "email-change-token"
}
Response: 200 OK
{
  "message": "Email changed successfully"
}
```

**New Database Table:**

```sql
CREATE TABLE email_change_requests (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    old_email VARCHAR(255) NOT NULL,
    new_email VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_email_change_user_id ON email_change_requests(user_id);
CREATE INDEX idx_email_change_token_hash ON email_change_requests(token_hash)
    WHERE verified_at IS NULL;
```

**Security Considerations:**

1. **Require current password** (prevent account takeover)
2. **Send notification to old email** (alert user of change)
3. **Verify new email** (ensure user owns new email)
4. **Check new email doesn't exist** (prevent duplicate accounts)
5. **Revoke all sessions** (force re-login with new email)
6. **Audit log** (record email change event)

**Implementation Priority:** 🟢 P2 (Quarter 2)

**Estimated Effort:** 2-3 days

---

## Scalability & Performance Enhancements

### 1. Database Optimization

**Current State:**
- ✅ Good indexes already in place
- ✅ Bun ORM (efficient)
- ⚠️ No query performance monitoring
- ⚠️ No connection pooling configuration

**Recommendations:**

#### 1a. Connection Pooling

```go
// cmd/auth-service/main.go

sqlDB := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))

// Configure connection pool
sqlDB.SetMaxOpenConns(25)                  // Max connections to DB
sqlDB.SetMaxIdleConns(10)                  // Keep 10 idle connections
sqlDB.SetConnMaxLifetime(5 * time.Minute)  // Recycle connections every 5 min
sqlDB.SetConnMaxIdleTime(10 * time.Minute) // Close idle conns after 10 min
```

**Tuning Guidelines:**
```
Max Open Connections = (CPU cores × 2) + effective_spindle_count
For cloud DB with 4 vCPUs: 25-50 connections recommended
```

#### 1b. Query Performance Monitoring

```go
// internal/app/middleware/db_metrics.go

type QueryMetrics struct {
    Duration time.Duration
    Query    string
    Error    error
}

db.AddQueryHook(&QueryMetricsHook{
    OnQuery: func(ctx context.Context, event *bun.QueryEvent) {
        duration := time.Since(event.StartTime)

        // Log slow queries (> 100ms)
        if duration > 100*time.Millisecond {
            logger.WithFields(logrus.Fields{
                "query":    event.Query,
                "duration": duration,
            }).Warn("Slow query detected")
        }

        // Prometheus metric
        metrics.DatabaseQueryDuration.Observe(duration.Seconds())
    },
})
```

#### 1c. Read Replicas (Future)

For read-heavy workloads:

```go
// Use primary for writes, replicas for reads
primaryDB := bun.NewDB(primarySQLDB, pgdialect.New())
replicaDB := bun.NewDB(replicaSQLDB, pgdialect.New())

// Repository pattern
func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
    return r.replicaDB.NewSelect().Model(&User{}).Where("id = ?", id).Scan(ctx)
}

func (r *UserRepository) UpdateUser(ctx context.Context, user *User) error {
    return r.primaryDB.NewUpdate().Model(user).WherePK().Exec(ctx)
}
```

#### 1d. Prepared Statements

Bun already uses prepared statements, but verify for hot paths:

```go
// Prepare once, execute many times
stmt := db.NewSelect().Model(&User{}).Where("email = ?", "").Prepare()
defer stmt.Close()

for _, email := range emails {
    var user User
    stmt.Scan(ctx, &user, email)
}
```

---

### 2. Redis Optimization

**Current State:**
- ✅ Redis used for OTP, sessions
- ⚠️ No connection pooling config
- ⚠️ No Redis cluster support
- ⚠️ No memory eviction policy configured

**Recommendations:**

#### 2a. Redis Configuration

```go
redisClient := redis.NewClient(&redis.Options{
    Addr:         fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
    Password:     cfg.Redis.Password,
    DB:           cfg.Redis.DB,

    // Connection pool
    PoolSize:     50,              // Max connections
    MinIdleConns: 10,              // Keep idle connections
    MaxRetries:   3,               // Retry failed commands
    DialTimeout:  5 * time.Second,
    ReadTimeout:  3 * time.Second,
    WriteTimeout: 3 * time.Second,

    // Connection pool timeout
    PoolTimeout:  4 * time.Second,
})
```

#### 2b. Redis Cluster Support (High Availability)

```go
// For production with Redis Cluster
redisClient := redis.NewClusterClient(&redis.ClusterOptions{
    Addrs: []string{
        "redis-node1:6379",
        "redis-node2:6379",
        "redis-node3:6379",
    },
    Password: cfg.Redis.Password,
    PoolSize: 50,
})
```

#### 2c. Memory Eviction Policy

**Redis configuration (redis.conf):**
```
maxmemory 2gb
maxmemory-policy allkeys-lru  # Evict least recently used keys

# For session/OTP cache (prefer LRU)
# allkeys-lru: Evict any key, LRU algorithm
# volatile-lru: Evict only keys with expiration, LRU
```

**Monitoring:**
```bash
# Check memory usage
redis-cli INFO memory

# Monitor evictions
redis-cli INFO stats | grep evicted_keys
```

---

### 3. Horizontal Scaling Architecture

**Current State:**
- ✅ Stateless HTTP service (can scale horizontally)
- ✅ Outbox worker (single instance safe)
- ⚠️ No load balancer configuration
- ⚠️ No distributed worker coordination

**Recommendations:**

#### 3a. Load Balancer Setup

**Option 1: Nginx**

```nginx
upstream auth_service {
    least_conn;  # Load balancing algorithm

    server auth-service-1:8080 max_fails=3 fail_timeout=30s;
    server auth-service-2:8080 max_fails=3 fail_timeout=30s;
    server auth-service-3:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name auth.yourdomain.com;

    location / {
        proxy_pass http://auth_service;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Health check
        proxy_next_upstream error timeout http_502 http_503 http_504;
    }

    location /health {
        proxy_pass http://auth_service/health;
        access_log off;
    }
}
```

**Option 2: Kubernetes Ingress**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
spec:
  type: ClusterIP
  selector:
    app: auth-service
  ports:
    - port: 8080
      targetPort: 8080

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-service-ingress
  annotations:
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  rules:
    - host: auth.yourdomain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: auth-service
                port:
                  number: 8080
```

#### 3b. Distributed Outbox Worker

**Problem:** Multiple worker instances could process same outbox rows

**Solution: Distributed Locking**

**Option 1: PostgreSQL Advisory Locks**

```go
// internal/worker/outbox_relay.go

func (r *OutboxRelay) processRow(ctx context.Context, row *OutboxRow) error {
    // Try to acquire lock
    locked, err := r.repo.AcquireAdvisoryLock(ctx, row.ID)
    if err != nil || !locked {
        return nil // Another worker has it
    }
    defer r.repo.ReleaseAdvisoryLock(ctx, row.ID)

    // Process row
    err = r.publishToRabbitMQ(row)
    // ...
}
```

```sql
-- PostgreSQL advisory lock
SELECT pg_try_advisory_lock(hashtext(id::TEXT))
FROM email_outbox
WHERE id = $1;

-- Release lock
SELECT pg_advisory_unlock(hashtext(id::TEXT));
```

**Option 2: Redis-based Distributed Lock**

```go
import "github.com/bsm/redislock"

locker := redislock.New(redisClient)

func (r *OutboxRelay) processRow(ctx context.Context, row *OutboxRow) error {
    lockKey := fmt.Sprintf("outbox:lock:%s", row.ID)

    lock, err := locker.Obtain(ctx, lockKey, 30*time.Second, nil)
    if err == redislock.ErrNotObtained {
        return nil // Another worker has lock
    }
    defer lock.Release(ctx)

    // Process row
}
```

**Option 3: SELECT FOR UPDATE SKIP LOCKED** (Recommended)

```go
// Simplest approach: Use PostgreSQL row-level locking
rows, err := db.NewSelect().
    Model(&OutboxRow{}).
    Where("status = ?", "pending").
    OrderExpr("created_at ASC").
    Limit(batchSize).
    For("UPDATE SKIP LOCKED"). // Skip rows locked by other workers
    Scan(ctx)
```

**Benefits:**
- ✅ No duplicate processing
- ✅ Safe for multiple worker instances
- ✅ Built into PostgreSQL

#### 3c. Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3  # Scale horizontally
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
        - name: auth-service
          image: auth-service:latest
          ports:
            - containerPort: 8080
          env:
            - name: DATABASE_HOST
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: db-host
            - name: DATABASE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: db-password
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /health/liveness
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health/readiness
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

---

### 4. Caching Strategy for Performance

**Hot Path Caching:**

```go
// Cache user profile for 5 minutes
func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
    cacheKey := fmt.Sprintf("user:%s", id)

    // Try cache
    cached, err := r.redis.Get(ctx, cacheKey).Result()
    if err == nil {
        var user User
        json.Unmarshal([]byte(cached), &user)
        return &user, nil
    }

    // Cache miss, query DB
    var user User
    err = r.db.NewSelect().Model(&user).Where("id = ?", id).Scan(ctx)
    if err != nil {
        return nil, err
    }

    // Store in cache
    data, _ := json.Marshal(user)
    r.redis.Set(ctx, cacheKey, data, 5*time.Minute)

    return &user, nil
}

// Invalidate cache on update
func (r *UserRepository) UpdateUser(ctx context.Context, user *User) error {
    err := r.db.NewUpdate().Model(user).WherePK().Exec(ctx)
    if err != nil {
        return err
    }

    // Invalidate cache
    cacheKey := fmt.Sprintf("user:%s", user.ID)
    r.redis.Del(ctx, cacheKey)

    return nil
}
```

**Cache Patterns:**

1. **Cache-Aside (Lazy Loading)** ✅ Current recommendation
   - Read: Check cache → Miss → Query DB → Store in cache
   - Write: Update DB → Invalidate cache

2. **Write-Through**
   - Write: Update DB → Update cache
   - Read: Check cache → Always hit

3. **Write-Behind**
   - Write: Update cache → Async update DB
   - Complex, high risk

---

### 5. API Response Compression

**Enable gzip compression:**

```go
import "github.com/go-chi/chi/v5/middleware"

r.Use(middleware.Compress(5)) // Compression level 1-9
```

**Benefits:**
- ✅ Reduce bandwidth by 70-90%
- ✅ Faster response times
- ⚠️ Slight CPU overhead (negligible)

---

## Security Hardening

### 1. Security Headers

**Add middleware for security headers:**

```go
// internal/app/middleware/security_headers.go

func SecurityHeaders() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Prevent clickjacking
            w.Header().Set("X-Frame-Options", "DENY")

            // Prevent MIME sniffing
            w.Header().Set("X-Content-Type-Options", "nosniff")

            // XSS protection (legacy browsers)
            w.Header().Set("X-XSS-Protection", "1; mode=block")

            // Referrer policy
            w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

            // Content Security Policy
            w.Header().Set("Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")

            // HSTS (HTTPS only)
            if r.TLS != nil {
                w.Header().Set("Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains; preload")
            }

            // Permissions policy
            w.Header().Set("Permissions-Policy",
                "geolocation=(), microphone=(), camera=()")

            next.ServeHTTP(w, r)
        })
    }
}
```

**Register middleware:**
```go
r.Use(appMiddleware.SecurityHeaders())
```

---

### 2. Input Sanitization

**Prevent SQL Injection:**
- ✅ Already using parameterized queries (Bun ORM)
- ✅ No raw SQL concatenation

**Prevent XSS:**
```go
import "html"

func sanitizeUserInput(input string) string {
    return html.EscapeString(input)
}
```

**Validate all inputs:**
```go
import "github.com/go-playground/validator/v10"

var validate = validator.New()

func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
    var req SignupRequest
    json.NewDecoder(r.Body).Decode(&req)

    // Validate
    err := validate.Struct(req)
    if err != nil {
        // Return validation errors
    }

    // Sanitize inputs
    req.Name = sanitizeUserInput(req.Name)
}
```

---

### 3. Secrets Management

**Current State:**
- ⚠️ JWT keys in filesystem
- ⚠️ Database password in config file
- ⚠️ No secret rotation strategy

**Recommendations:**

**Option 1: Environment Variables** (Current + Production)
```bash
export DATABASE_PASSWORD="secure-password"
export JWT_PRIVATE_KEY="$(cat private_key.pem)"
export REDIS_PASSWORD="redis-password"
```

**Option 2: HashiCorp Vault** (Enterprise)
```go
import "github.com/hashicorp/vault/api"

vaultClient, _ := api.NewClient(api.DefaultConfig())
secret, _ := vaultClient.Logical().Read("secret/data/auth-service")

dbPassword := secret.Data["data"].(map[string]interface{})["db_password"].(string)
```

**Option 3: AWS Secrets Manager / GCP Secret Manager**
```go
import "github.com/aws/aws-sdk-go/service/secretsmanager"

svc := secretsmanager.New(session.New())
result, _ := svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
    SecretId: aws.String("auth-service/database"),
})

dbPassword := *result.SecretString
```

**Option 4: Kubernetes Secrets**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-secrets
type: Opaque
data:
  db-password: <base64-encoded>
  jwt-private-key: <base64-encoded>
```

**JWT Key Rotation Strategy:**

```
1. Generate new key pair (keep old key)
2. Sign new tokens with new key
3. Validate tokens with both old and new keys (transition period)
4. After all tokens expire (7 days), remove old key
```

```go
type JWTManager struct {
    currentKey  *rsa.PrivateKey
    previousKey *rsa.PrivateKey
    publicKeys  []*rsa.PublicKey // Both current and previous
}

func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
    // Try both keys
    for _, pubKey := range m.publicKeys {
        token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
            return pubKey, nil
        })
        if err == nil {
            return token.Claims.(*Claims), nil
        }
    }
    return nil, errors.New("invalid token")
}
```

---

### 4. API Security Best Practices

**4a. HTTPS Only (Production)**

```go
// Redirect HTTP to HTTPS
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
    target := "https://" + r.Host + r.URL.Path
    if r.URL.RawQuery != "" {
        target += "?" + r.URL.RawQuery
    }
    http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// Start both HTTP (redirect) and HTTPS
go http.ListenAndServe(":80", http.HandlerFunc(redirectToHTTPS))
http.ListenAndServeTLS(":443", "cert.pem", "key.pem", r)
```

**4b. API Keys for Service-to-Service**

```sql
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    scopes JSONB NOT NULL,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

```go
// Middleware to validate API key
func APIKeyAuth(repo APIKeyRepository) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            apiKey := r.Header.Get("X-API-Key")
            if apiKey == "" {
                http.Error(w, "Missing API key", http.StatusUnauthorized)
                return
            }

            keyHash := sha256Hash(apiKey)
            valid, err := repo.ValidateAPIKey(r.Context(), keyHash)
            if err != nil || !valid {
                http.Error(w, "Invalid API key", http.StatusUnauthorized)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

---

### 5. Penetration Testing Checklist

**Before production, test for:**

| Vulnerability | Test Method | Status |
|---------------|-------------|--------|
| SQL Injection | sqlmap, manual payloads | ⚠️ TODO |
| XSS | XSS payloads in all inputs | ⚠️ TODO |
| CSRF | Missing CSRF tokens | ⚠️ TODO |
| Authentication Bypass | Tamper JWT tokens | ⚠️ TODO |
| Broken Access Control | Access other user's data | ⚠️ TODO |
| Sensitive Data Exposure | Check logs, errors for secrets | ⚠️ TODO |
| XXE | XML external entity attacks | ✅ N/A (no XML) |
| Insecure Deserialization | Malicious JSON payloads | ⚠️ TODO |
| Rate Limiting | Brute force attacks | ❌ CRITICAL |
| Password Policy | Weak passwords accepted? | ✅ Done |

**Tools:**
- **OWASP ZAP** - Automated vulnerability scanner
- **Burp Suite** - Manual penetration testing
- **sqlmap** - SQL injection testing
- **Postman/Newman** - API security testing

---

## Operational Excellence

### 1. Logging Best Practices

**Current State:**
- ✅ Structured JSON logging (Logrus)
- ✅ Request ID propagation
- ⚠️ No log levels per endpoint
- ⚠️ Sensitive data may be logged

**Recommendations:**

**1a. Log Levels:**
```
DEBUG: Detailed information for debugging
INFO:  General informational messages
WARN:  Warning messages (recoverable errors)
ERROR: Error messages (requires attention)
FATAL: Critical errors (service crash)
```

**1b. Sensitive Data Redaction:**
```go
type SanitizedUser struct {
    ID    uuid.UUID `json:"id"`
    Email string    `json:"email"`
    // NEVER log: password, password_hash, tokens, OTPs
}

logger.WithFields(logrus.Fields{
    "user_id": user.ID,
    "email":   user.Email,
    // "password": user.Password, ❌ NEVER
}).Info("User logged in")
```

**1c. Centralized Logging:**

**Option 1: ELK Stack**
- **Elasticsearch** - Store logs
- **Logstash** - Process logs
- **Kibana** - Visualize logs

**Option 2: Grafana Loki** (Recommended for Kubernetes)
```yaml
# Fluent Bit → Loki → Grafana
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
data:
  fluent-bit.conf: |
    [OUTPUT]
        Name loki
        Match *
        Url http://loki:3100/loki/api/v1/push
```

**Option 3: Cloud-Based**
- **AWS CloudWatch Logs**
- **Google Cloud Logging**
- **Datadog**

**1d. Structured Logging Example:**
```go
logger.WithFields(logrus.Fields{
    "user_id":    userID,
    "action":     "login",
    "method":     "password",
    "ip_address": ip,
    "user_agent": userAgent,
    "status":     "success",
    "duration_ms": duration.Milliseconds(),
    "request_id": requestID,
}).Info("User login successful")
```

---

### 2. Alerting Strategy

**Critical Alerts (Page On-Call):**
```
- Service down (all instances)
- Database connection failure
- Redis connection failure
- RabbitMQ connection failure
- High error rate (>5%)
- P95 latency > 1000ms
```

**Warning Alerts (Investigate Next Day):**
```
- High login failure rate
- Outbox backlog > 1000
- Disk space > 80%
- Memory usage > 80%
- Account lockout spike
- Suspicious login patterns
```

**Alerting Channels:**
```
Critical: PagerDuty, SMS, Phone Call
Warning:  Slack, Email
Info:     Slack, Dashboard
```

**Prometheus Alert Rules:**
```yaml
groups:
  - name: auth_service_critical
    rules:
      - alert: ServiceDown
        expr: up{job="auth-service"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Auth service is down"

      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High error rate (>5%)"

      - alert: DatabaseConnectionFailure
        expr: database_connection_errors_total > 10
        for: 1m
        labels:
          severity: critical
```

---

### 3. Backup & Disaster Recovery

**Database Backups:**

**Automated Daily Backups:**
```bash
#!/bin/bash
# scripts/backup_db.sh

DATE=$(date +%Y-%m-%d_%H-%M-%S)
BACKUP_FILE="auth_db_backup_$DATE.sql.gz"

pg_dump -h $DB_HOST -U $DB_USER $DB_NAME | gzip > /backups/$BACKUP_FILE

# Upload to S3
aws s3 cp /backups/$BACKUP_FILE s3://your-backups/auth-service/

# Retain 30 days of backups
find /backups -name "auth_db_backup_*.sql.gz" -mtime +30 -delete
```

**Backup Strategy:**
```
Daily:   Full backup at 2 AM UTC
Weekly:  Full backup + retention for 3 months
Monthly: Archive backup + retention for 1 year
```

**Point-in-Time Recovery (PostgreSQL):**
Enable WAL archiving:
```
# postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'aws s3 cp %p s3://your-wal-archive/%f'
```

**Restore Testing:**
```
# Test restore every quarter
pg_restore -d auth_service_test backup.sql
# Verify data integrity
psql -d auth_service_test -c "SELECT COUNT(*) FROM users;"
```

**Redis Backup:**
```
# Enable RDB snapshots
save 900 1      # Save if 1 key changed in 15 min
save 300 10     # Save if 10 keys changed in 5 min
save 60 10000   # Save if 10k keys changed in 1 min
```

---

### 4. Monitoring Dashboard

**Key Metrics to Display:**

**Business Metrics:**
```
- Total users
- Active users (last 30 days)
- Signups today/week/month
- Login success rate
- 2FA adoption rate
- Password reset requests
```

**Technical Metrics:**
```
- Request rate (requests/sec)
- Error rate (%)
- P50, P95, P99 latency
- Active database connections
- Redis hit rate
- Outbox pending count
- RabbitMQ queue depth
```

**Security Metrics:**
```
- Failed login attempts
- Account lockouts
- Suspicious login attempts
- Rate limit violations
- Token refresh rate
```

**Grafana Dashboard Example:**
```json
{
  "dashboard": {
    "title": "Auth Service - Overview",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~\"5..\"}[5m]) / rate(http_requests_total[5m])"
          }
        ]
      }
    ]
  }
}
```

---

### 5. Documentation Standards

**Required Documentation:**

1. **API Documentation** ✅ (Swagger already exists)
   - Keep Swagger annotations up to date
   - Add example requests/responses
   - Document error codes

2. **Architecture Documentation** (This document)
   - System design
   - Data flow diagrams
   - Database schema
   - Deployment architecture

3. **Runbook** ⚠️ TODO
   - How to deploy
   - How to rollback
   - How to scale
   - How to troubleshoot common issues

4. **Security Documentation** ⚠️ TODO
   - Threat model
   - Security controls
   - Incident response plan
   - Compliance documentation (GDPR, SOC2)

5. **Developer Onboarding** ⚠️ TODO
   - Setup local environment
   - Code structure walkthrough
   - How to run tests
   - How to contribute

---

## Implementation Roadmap

### Phase 1: Critical Security & Quality (Weeks 1-4)

**Week 1:**
- ✅ Implement HTTP rate limiting (P0)
- ✅ Add password reset endpoints (P0)
- ✅ Enhanced health checks (P1)

**Week 2-4:**
- ✅ Write comprehensive test suite (P0)
  - Week 2: Unit tests (utils, repositories)
  - Week 3: Service layer tests
  - Week 4: Integration & E2E tests
- ✅ Add Prometheus metrics (P1)
- ✅ Implement proper error handling with error codes

**Deliverables:**
- ✅ Rate limiting active on all endpoints
- ✅ Password reset flow fully functional
- ✅ 70%+ test coverage
- ✅ Metrics exposed at `/metrics`
- ✅ Health checks validate dependencies

---

### Phase 2: User Management & Observability (Weeks 5-8)

**Week 5:**
- ✅ Complete user management endpoints (P1)
- ✅ Admin audit log viewing endpoint (P2)
- ✅ Email change flow (P2)

**Week 6:**
- ✅ Background job system (session cleanup, token cleanup)
- ✅ Anomaly detection (basic implementation)

**Week 7-8:**
- ✅ OpenTelemetry tracing integration
- ✅ Grafana dashboards
- ✅ Alerting rules (Prometheus Alertmanager)

**Deliverables:**
- ✅ Full user management API
- ✅ Admin endpoints secured with RBAC
- ✅ Distributed tracing operational
- ✅ Monitoring dashboards deployed

---

### Phase 3: Advanced Features (Weeks 9-16)

**Weeks 9-12: OAuth2/OIDC Provider**
- ✅ OAuth2 client registration
- ✅ Authorization code flow
- ✅ PKCE support
- ✅ OIDC discovery endpoint
- ✅ Token introspection
- ✅ User consent management

**Weeks 13-16: WebAuthn/Passkeys**
- ✅ WebAuthn registration
- ✅ WebAuthn authentication
- ✅ Credential management
- ✅ Fallback authentication methods

**Deliverables:**
- ✅ Auth service can act as OAuth2 provider
- ✅ Passwordless authentication via WebAuthn
- ✅ Comprehensive documentation

---

### Phase 4: Scalability & Security (Weeks 17-24)

**Weeks 17-19: Social Login**
- ✅ Google OAuth integration
- ✅ GitHub OAuth integration
- ✅ Apple Sign In
- ✅ Account linking

**Weeks 20-21: Magic Link**
- ✅ Magic link authentication
- ✅ Email template design

**Weeks 22-24: Multi-Tenancy**
- ✅ Tenant model & database
- ✅ Tenant middleware
- ✅ PostgreSQL RLS policies
- ✅ Tenant isolation testing

**Deliverables:**
- ✅ Multiple social login providers supported
- ✅ Magic link authentication available
- ✅ Multi-tenant architecture operational

---

### Phase 5: Polish & Hardening (Weeks 25-28)

**Week 25-26:**
- ✅ Security headers middleware
- ✅ CAPTCHA integration
- ✅ Device fingerprinting
- ✅ Geo-location tracking

**Week 27:**
- ✅ API documentation review and updates
- ✅ Runbook creation
- ✅ Security documentation

**Week 28:**
- ✅ Penetration testing
- ✅ Performance testing
- ✅ Production readiness review

**Deliverables:**
- ✅ Production-ready authentication service
- ✅ Comprehensive documentation
- ✅ Security audit passed
- ✅ Performance benchmarks met

---

## Technical Debt

### Current Technical Debt

1. **No Test Coverage**
   - **Impact:** High risk of regressions
   - **Effort:** 3-4 weeks
   - **Priority:** P0

2. **No Rate Limiting**
   - **Impact:** Security vulnerability
   - **Effort:** 2-3 days
   - **Priority:** P0

3. **Basic Health Checks**
   - **Impact:** Cannot detect degraded state
   - **Effort:** 1 day
   - **Priority:** P1

4. **No Metrics**
   - **Impact:** Cannot monitor performance
   - **Effort:** 1 week
   - **Priority:** P1

5. **Incomplete API Coverage**
   - **Impact:** Missing features (password reset, user management)
   - **Effort:** 1 week
   - **Priority:** P1

### Preventing Future Technical Debt

**Policies:**
1. **No feature without tests** (min 70% coverage)
2. **All endpoints require rate limiting** (security)
3. **All endpoints instrumented** (metrics)
4. **API changes require documentation update**
5. **Security review for authentication changes**

---

## Conclusion

### Summary

The **auth1** authentication service demonstrates excellent architectural foundations with clean code, strong security primitives, and production-ready patterns like the transactional outbox. However, several critical gaps exist that must be addressed before production deployment:

**Critical (Address Immediately):**
1. HTTP rate limiting (security vulnerability)
2. Test coverage (quality/reliability risk)
3. Password reset endpoints (UX gap)
4. Enhanced health checks (operational risk)

**High Priority (Address Soon):**
1. Observability (metrics, tracing, dashboards)
2. User management API completion
3. Security hardening (anomaly detection, CAPTCHA)

**Future Enhancements:**
1. OAuth2/OIDC provider capabilities
2. WebAuthn/Passkeys for passwordless auth
3. Social login integration
4. Multi-tenancy architecture
5. Magic link authentication

### Next Steps

1. **Review this document** with the development team
2. **Prioritize features** based on business requirements
3. **Create detailed tickets** for each enhancement
4. **Begin Phase 1 implementation** (Weeks 1-4)
5. **Establish metrics** for measuring progress
6. **Schedule security review** after Phase 1 completion

### Success Metrics

**Security:**
- Zero critical vulnerabilities in penetration test
- Rate limiting active on all endpoints
- 100% of sensitive operations logged

**Quality:**
- 70%+ test coverage
- All critical paths covered by integration tests
- Zero high-severity bugs in production

**Performance:**
- P95 latency < 200ms
- 99.9% uptime
- Successful horizontal scaling to 10+ instances

**Observability:**
- All key metrics tracked
- Alerts configured for critical failures
- Mean time to detection < 5 minutes

### Resources

**Documentation:**
- [Auth Service README](./README.md)
- [Quick Start Guide](./QUICK_START.md)
- [Platform-Agnostic Guide](./PLATFORM_AGNOSTIC_GUIDE.md)
- [Swagger Documentation](http://localhost:8080/swagger/index.html)

**References:**
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Spec](https://openid.net/specs/openid-connect-core-1_0.html)
- [WebAuthn Spec](https://www.w3.org/TR/webauthn-2/)
- [Go Best Practices](https://golang.org/doc/effective_go)

---

**End of Document**

*This architecture enhancement plan is a living document and should be reviewed quarterly.*
