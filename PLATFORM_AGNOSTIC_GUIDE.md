# Platform-Agnostic Authentication Service

This authentication service has been enhanced to be **fully platform-agnostic**, allowing you to use it across different applications and platforms without modification. It provides a comprehensive, secure, and flexible authentication system.

## Table of Contents

1. [What's New](#whats-new)
2. [Core Features](#core-features)
3. [Architecture](#architecture)
4. [Getting Started](#getting-started)
5. [Configuration](#configuration)
6. [Authentication Methods](#authentication-methods)
7. [Role-Based Access Control](#role-based-access-control)
8. [User Metadata](#user-metadata)
9. [Security Features](#security-features)
10. [API Reference](#api-reference)
11. [Platform Integration](#platform-integration)
12. [Migration Guide](#migration-guide)

---

## What's New

### Enhanced Database Schema
- **Account Security**: `failed_login_attempts`, `locked_until`, `is_active`
- **Verification Tracking**: `email_verified_at`, `phone_verified_at`
- **Password Management**: `password_changed_at`, `must_change_password`, `last_password_reset_at`
- **Role-Based Access Control**: `role` field with customizable permissions
- **Platform-Agnostic Storage**: `metadata` JSONB field for custom platform-specific data
- **Audit Logging**: Complete audit trail for security events
- **Soft Deletion**: `deleted_at` for data retention compliance

### New Tables
- **`refresh_tokens`**: Secure refresh token management
- **`sessions`**: Active session tracking
- **`password_reset_tokens`**: Password reset flow
- **`audit_logs`**: Comprehensive audit logging

### New Features
1. **Phone-Based Authentication**: Full support for phone number registration and login
2. **SMS Integration**: OTP delivery via SMS
3. **Password Reset**: Complete password reset workflow
4. **Account Locking**: Automatic account locking after failed attempts
5. **RBAC System**: Flexible role and permission management
6. **Custom Metadata**: Store platform-specific user data
7. **Audit Logging**: Track all security-relevant events
8. **Multiple Authentication Methods**: Email, Phone, Password, OTP, 2FA

---

## Core Features

### Authentication Methods
- ✅ Email + Password
- ✅ Phone + Password
- ✅ Email + OTP (One-Time Password)
- ✅ Phone + SMS OTP
- ✅ Two-Factor Authentication (2FA/TOTP)
- ✅ Password Reset via Email/SMS
- ✅ Session Management
- ✅ JWT Access & Refresh Tokens

### Security Features
- ✅ Account Locking after Failed Attempts
- ✅ Password Policy Enforcement
- ✅ Password Strength Validation
- ✅ JWT RS256 Signing
- ✅ Refresh Token Rotation
- ✅ Session Tracking with Device Info
- ✅ IP Address & User Agent Logging
- ✅ Audit Logging
- ✅ Soft Delete for GDPR Compliance

### User Management
- ✅ Role-Based Access Control (RBAC)
- ✅ Custom User Roles
- ✅ Permission System
- ✅ User Metadata (Platform-Specific Fields)
- ✅ Account Activation/Deactivation
- ✅ Soft Delete

---

## Architecture

```
┌─────────────────┐
│   Application   │
│   (Any Platform)│
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│   Auth Service API          │
│   - JWT Authentication      │
│   - RBAC                    │
│   - Audit Logging           │
└─────────────┬───────────────┘
              │
    ┌─────────┼──────────┐
    ▼         ▼          ▼
┌──────┐  ┌──────┐  ┌──────┐
│ Postgres│ Redis │ Email/SMS│
└────────┘  └─────┘  └──────┘
```

---

## Getting Started

### Prerequisites
- Go 1.21+
- PostgreSQL 15+
- Redis 7+
- Email Service (HTTP API)
- SMS Service (Optional, HTTP API)

### Quick Setup

1. **Clone and Navigate**
   ```bash
   cd services/auth-service
   ```

2. **Generate JWT Keys**
   ```bash
   chmod +x scripts/generate_keys.sh
   ./scripts/generate_keys.sh
   ```

3. **Configure the Service**
   ```bash
   cp config.example.yaml config.yaml
   # Edit config.yaml with your settings
   ```

4. **Run Migrations**
   ```bash
   # Ensure PostgreSQL is running
   ./scripts/migrate.sh init
   ./scripts/migrate.sh up
   ```

5. **Start the Service**
   ```bash
   # Using Docker Compose (recommended)
   docker-compose up -d
   
   # Or run directly
   go run cmd/auth-service/main.go
   ```

---

## Configuration

### Feature Flags

Enable/disable authentication methods based on your platform needs:

```yaml
app:
  # Authentication Methods
  enable_email_auth: true          # Email-based registration/login
  enable_phone_auth: false         # Phone-based registration/login
  enable_password_auth: true       # Password-based login
  enable_otp_auth: true            # OTP-based login
  enable_2fa: true                 # Two-Factor Authentication
  
  # Verification Requirements
  require_email_verification: true
  require_phone_verification: false
  
  # Features
  enable_audit_log: true           # Log security events
```

### Security Configuration

```yaml
security:
  max_login_attempts: 5                  # Lock account after N failures
  lockout_duration_minutes: 30           # How long to lock account
  password_min_length: 8
  password_require_upper: true
  password_require_lower: true
  password_require_number: true
  password_require_special: false
  password_reset_ttl: 60                 # Password reset token validity (minutes)
```

### SMS Configuration

```yaml
sms:
  service_url: "http://your-sms-service:8082"
  timeout: 30
  retry_count: 3
  provider: "twilio"  # or "nexmo", "sns", etc.
```

---

## Authentication Methods

### 1. Email + Password

**Signup:**
```bash
POST /api/v1/auth/signup
{
  "email": "user@example.com",
  "name": "John Doe",
  "password": "SecurePass123",
  "role": "user",  # Optional, defaults to "user"
  "metadata": {    # Optional platform-specific data
    "referral_code": "ABC123",
    "signup_source": "web"
  }
}
```

**Verify Signup:**
```bash
POST /api/v1/auth/verify-signup
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Login:**
```bash
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

### 2. Phone + Password

**Signup:**
```bash
POST /api/v1/auth/signup-phone
{
  "phone": "+8801712345678",
  "name": "John Doe",
  "password": "SecurePass123",
  "metadata": {
    "country": "BD"
  }
}
```

**Verify Signup:**
```bash
POST /api/v1/auth/verify-phone-signup
{
  "phone": "+8801712345678",
  "otp": "123456"
}
```

**Login:**
```bash
POST /api/v1/auth/login-phone
{
  "phone": "+8801712345678",
  "password": "SecurePass123"
}
```

### 3. OTP-Based Login

**Request OTP:**
```bash
POST /api/v1/auth/request-otp
{
  "email": "user@example.com",  # Or "phone": "+8801712345678"
  "purpose": "login"
}
```

**Verify OTP:**
```bash
POST /api/v1/auth/verify-login
{
  "email": "user@example.com",
  "otp": "123456"
}
```

### 4. Password Reset

**Request Reset:**
```bash
POST /api/v1/auth/request-password-reset
{
  "email": "user@example.com"  # Or "phone": "+8801712345678"
}
```

**Reset Password:**
```bash
POST /api/v1/auth/reset-password
{
  "token": "reset-token-from-email",
  "new_password": "NewSecurePass456"
}
```

**Change Password (Authenticated):**
```bash
POST /api/v1/auth/change-password
Authorization: Bearer <access_token>
{
  "old_password": "OldPass123",
  "new_password": "NewSecurePass456"
}
```

---

## Role-Based Access Control

### Default Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| **user** | Standard user | Read/write own profile |
| **moderator** | Content moderator | Moderate content, ban users |
| **reviewer** | Verification reviewer | Review verifications |
| **admin** | System administrator | Full system access |

### Custom Roles

Create custom roles programmatically:

```go
import "auth-service/internal/utils"

rbac := utils.NewRBACManager()

// Create custom role
rbac.CreateCustomRole("premium_user", []utils.Permission{
    utils.PermissionReadOwnProfile,
    utils.PermissionWriteOwnProfile,
    "premium:features:access",  // Custom permission
})

// Add permission to existing role
rbac.AddCustomPermission("user", "beta:features:access")
```

### Checking Permissions

```go
rbac := utils.NewRBACManager()

if rbac.HasPermission(user.Role, utils.PermissionManageUsers) {
    // Allow action
}
```

### Update User Role

```bash
POST /api/v1/admin/users/:userId/role
Authorization: Bearer <admin_token>
{
  "role": "moderator"
}
```

---

## User Metadata

Store platform-specific data using the `metadata` JSONB field:

### Examples

**E-commerce Platform:**
```json
{
  "metadata": {
    "customer_tier": "gold",
    "loyalty_points": 1500,
    "preferred_payment": "card",
    "shipping_addresses": [...]
  }
}
```

**Matrimony Platform (Duitara):**
```json
{
  "metadata": {
    "profile_ids": ["uuid1", "uuid2"],
    "subscription_tier": "premium",
    "token_balance": 10,
    "preferences": {...}
  }
}
```

**SaaS Platform:**
```json
{
  "metadata": {
    "organization_id": "org_123",
    "team_role": "developer",
    "api_quota": 10000,
    "features_enabled": ["analytics", "export"]
  }
}
```

### Update Metadata

```bash
PUT /api/v1/users/:userId/metadata
Authorization: Bearer <access_token>
{
  "metadata": {
    "custom_field": "value",
    "nested": {
      "data": "here"
    }
  }
}
```

---

## Security Features

### Account Locking

Automatic account locking after failed login attempts:

- **Trigger**: Configurable failed attempts (default: 5)
- **Duration**: Configurable lockout (default: 30 minutes)
- **Unlock**: Automatic after duration or manual by admin

**Manual Unlock:**
```bash
POST /api/v1/admin/users/:userId/unlock
Authorization: Bearer <admin_token>
```

### Password Policy

Configure password requirements:

```go
policy := &utils.PasswordPolicy{
    MinLength:      8,
    RequireUpper:   true,
    RequireLower:   true,
    RequireNumber:  true,
    RequireSpecial: false,
}

err := policy.ValidatePassword("MyPassword123")
```

### Audit Logging

All security events are automatically logged:

- User registration
- Login attempts (success/failure)
- Password changes
- Account lockouts
- 2FA enable/disable
- Role changes
- Account deletion

**View Audit Logs:**
```bash
GET /api/v1/admin/audit-logs?user_id=<uuid>&event_type=user.login_failed
Authorization: Bearer <admin_token>
```

### Session Management

Track all active sessions with device information:

```bash
# Get active sessions
GET /api/v1/auth/sessions
Authorization: Bearer <access_token>

# Logout all devices
POST /api/v1/auth/logout-all
Authorization: Bearer <access_token>
```

---

## API Reference

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/signup` | Email signup |
| POST | `/api/v1/auth/signup-phone` | Phone signup |
| POST | `/api/v1/auth/verify-signup` | Verify email OTP |
| POST | `/api/v1/auth/verify-phone-signup` | Verify phone OTP |
| POST | `/api/v1/auth/login` | Email login |
| POST | `/api/v1/auth/login-phone` | Phone login |
| POST | `/api/v1/auth/request-otp` | Request OTP |
| POST | `/api/v1/auth/verify-login` | Verify login OTP |
| POST | `/api/v1/auth/request-password-reset` | Request password reset |
| POST | `/api/v1/auth/reset-password` | Reset password |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout |
| GET | `/api/v1/auth/public-key` | Get JWT public key |

### Protected Endpoints

| Method | Endpoint | Description | Required Role |
|--------|----------|-------------|---------------|
| GET | `/api/v1/auth/me` | Get current user | any |
| PUT | `/api/v1/auth/me` | Update profile | any |
| POST | `/api/v1/auth/change-password` | Change password | any |
| POST | `/api/v1/auth/2fa/setup` | Setup 2FA | any |
| POST | `/api/v1/auth/2fa/verify` | Verify 2FA | any |
| POST | `/api/v1/auth/2fa/disable` | Disable 2FA | any |
| GET | `/api/v1/auth/sessions` | Get active sessions | any |
| POST | `/api/v1/auth/logout-all` | Logout all devices | any |

### Admin Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/users/:id` | Get user details |
| PUT | `/api/v1/admin/users/:id/role` | Update user role |
| POST | `/api/v1/admin/users/:id/deactivate` | Deactivate account |
| POST | `/api/v1/admin/users/:id/reactivate` | Reactivate account |
| POST | `/api/v1/admin/users/:id/unlock` | Unlock account |
| DELETE | `/api/v1/admin/users/:id` | Soft delete user |
| GET | `/api/v1/admin/audit-logs` | Get audit logs |

---

## Platform Integration

### For Duitara (Matrimony Platform)

```yaml
# config.yaml
app:
  name: "duitara-auth"
  enable_email_auth: true
  enable_phone_auth: true
  enable_2fa: true
  require_email_verification: true
  require_phone_verification: true  # Important for matrimony

security:
  max_login_attempts: 5
  password_min_length: 8
  password_require_special: true
```

**User Creation with Duitara-Specific Metadata:**
```json
{
  "email": "user@example.com",
  "phone": "+8801712345678",
  "name": "John Doe",
  "password": "SecurePass123!",
  "metadata": {
    "platform": "duitara",
    "user_type": "groom",
    "guardian_id": null,
    "profile_ids": [],
    "token_balance": 0,
    "subscription_tier": "free"
  }
}
```

### For E-Commerce Platform

```yaml
app:
  enable_email_auth: true
  enable_phone_auth: false
  enable_2fa: false
  require_email_verification: true
  require_phone_verification: false
```

### For SaaS Platform

```yaml
app:
  enable_email_auth: true
  enable_phone_auth: false
  enable_2fa: true  # Important for SaaS security
  enable_audit_log: true
```

**Custom Permissions:**
```go
// Add organization-specific permissions
rbac.CreateCustomRole("org_admin", []utils.Permission{
    "org:manage",
    "org:billing",
    "org:members:invite",
    "org:members:remove",
})
```

---

## Migration Guide

### Migrating from auth1

If you're migrating from the original auth1 service:

1. **Run New Migrations:**
   ```bash
   ./scripts/migrate.sh up
   ```
   This adds all new fields to existing tables.

2. **Update Existing Users:**
   ```sql
   -- Set default values for existing users
   UPDATE users SET
     is_active = TRUE,
     role = 'user',
     metadata = '{}',
     failed_login_attempts = 0
   WHERE is_active IS NULL;
   ```

3. **Update Configuration:**
   - Add new config sections (sms, security)
   - Set feature flags appropriately

4. **Update Client Applications:**
   - Handle new response fields (role, metadata, etc.)
   - Implement RBAC checks if needed

---

## Best Practices

### Security
1. ✅ Always use HTTPS in production
2. ✅ Rotate JWT keys regularly (every 90 days)
3. ✅ Enable 2FA for admin accounts
4. ✅ Monitor audit logs regularly
5. ✅ Use strong password policies
6. ✅ Set appropriate lockout durations

### Performance
1. ✅ Use Redis for session caching
2. ✅ Implement connection pooling
3. ✅ Set appropriate JWT expiry times
4. ✅ Index metadata fields you query frequently

### Data Privacy
1. ✅ Use soft delete for GDPR compliance
2. ✅ Store minimal PII in metadata
3. ✅ Encrypt sensitive metadata fields
4. ✅ Implement data export APIs

---

## Support

For issues, questions, or contributions:
- GitHub Issues: [your-repo/issues]
- Documentation: [your-docs-url]
- Email: support@example.com

---

## License

MIT License - See LICENSE file for details

---

**Version:** 2.0 (Platform-Agnostic)  
**Last Updated:** May 20, 2026  
**Status:** Production Ready
