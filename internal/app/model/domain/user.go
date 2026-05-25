package domain

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the domain layer
type User struct {
	// Core identity fields
	ID           uuid.UUID  `json:"id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	Phone        *string    `json:"phone,omitempty"`
	PasswordHash *string    `json:"-"`
	
	// Verification and status fields
	IsVerified         bool       `json:"is_verified"`
	IsActive           bool       `json:"is_active"`
	EmailVerifiedAt    *time.Time `json:"email_verified_at,omitempty"`
	PhoneVerifiedAt    *time.Time `json:"phone_verified_at,omitempty"`
	DeletedAt          *time.Time `json:"deleted_at,omitempty"`
	
	// Security fields
	Is2FAEnabled         bool       `json:"is_2fa_enabled"`
	TOTPSecret           *string    `json:"-"`
	PasswordChangedAt    *time.Time `json:"password_changed_at,omitempty"`
	MustChangePassword   bool       `json:"must_change_password"`
	LastPasswordResetAt  *time.Time `json:"-"`
	
	// Role and permissions
	Role string `json:"role"`
	
	// Platform-agnostic metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	
	// Tracking fields
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	
	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsDeleted checks if the user is soft-deleted
func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil
}

// CanLogin checks if the user can log in
func (u *User) CanLogin() bool {
	return u.IsActive && !u.IsDeleted()
}

// PendingUser represents a user awaiting verification
type PendingUser struct {
	Email     string                 `json:"email"`
	Phone     *string                `json:"phone,omitempty"`
	Password  *string                `json:"-"`
	Name      string                 `json:"name"`
	Role      string                 `json:"role,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	ExpiresAt time.Time              `json:"expires_at"`
}

// OTPData represents OTP information
type OTPData struct {
	HashedOTP string    `json:"-"`
	Purpose   string    `json:"purpose"`
	ExpiresAt time.Time `json:"expires_at"`
	Identifier string   `json:"identifier"` // email or phone
	Type      string    `json:"type"`       // email or sms
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"` // Bearer
}

// RefreshTokenData represents refresh token metadata
type RefreshTokenData struct {
	UserID    uuid.UUID `json:"user_id"`
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TOTPSetupData represents 2FA setup information
type TOTPSetupData struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes,omitempty"`
}

// SessionInfo represents an active session stored in Redis.
type SessionInfo struct {
	JTI       string    `json:"session_id"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	Token       string    `json:"token"`
	UserID      uuid.UUID `json:"user_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// AuditEvent represents an audit log event
type AuditEvent struct {
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	EventType string                 `json:"event_type"`
	EventData map[string]interface{} `json:"event_data,omitempty"`
	IPAddress *string                `json:"ip_address,omitempty"`
	UserAgent *string                `json:"user_agent,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// Constants for user roles
const (
	RoleUser      = "user"
	RoleAdmin     = "admin"
	RoleModerator = "moderator"
	RoleReviewer  = "reviewer"
)

// Constants for audit event types
const (
	EventUserRegistered      = "user.registered"
	EventUserLogin           = "user.login"
	EventUserLoginFailed     = "user.login_failed"
	EventUserLogout          = "user.logout"
	EventUserLocked          = "user.locked"
	EventUserUnlocked        = "user.unlocked"
	EventPasswordChanged     = "user.password_changed"
	EventPasswordResetRequested = "user.password_reset_requested"
	EventPasswordReset       = "user.password_reset"
	Event2FAEnabled          = "user.2fa_enabled"
	Event2FADisabled         = "user.2fa_disabled"
	EventEmailVerified       = "user.email_verified"
	EventPhoneVerified       = "user.phone_verified"
	EventUserDeleted         = "user.deleted"
	EventUserReactivated     = "user.reactivated"
)
