package db

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// Metadata is a generic JSONB field for storing platform-specific data
type Metadata map[string]interface{}

// Value implements the driver.Valuer interface for database storage
func (m Metadata) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// Scan implements the sql.Scanner interface for database retrieval
func (m *Metadata) Scan(value interface{}) error {
	if value == nil {
		*m = make(Metadata)
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, m)
}

type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	// Core identity fields
	ID           uuid.UUID  `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	Email        string     `bun:"email,unique,notnull" json:"email"`
	Name         string     `bun:"name,notnull" json:"name"`
	Phone        *string    `bun:"phone,unique" json:"phone,omitempty"`
	PasswordHash *string    `bun:"password_hash" json:"-"`
	
	// Verification and status fields
	IsVerified         bool       `bun:"is_verified,notnull,default:false" json:"is_verified"`
	IsActive           bool       `bun:"is_active,notnull,default:true" json:"is_active"`
	EmailVerifiedAt    *time.Time `bun:"email_verified_at" json:"email_verified_at,omitempty"`
	PhoneVerifiedAt    *time.Time `bun:"phone_verified_at" json:"phone_verified_at,omitempty"`
	DeletedAt          *time.Time `bun:"deleted_at" json:"deleted_at,omitempty"`
	
	// Security fields
	Is2FAEnabled         bool       `bun:"is_2fa_enabled,notnull,default:false" json:"is_2fa_enabled"`
	TOTPSecret           *string    `bun:"totp_secret" json:"-"`
	FailedLoginAttempts  int        `bun:"failed_login_attempts,default:0" json:"-"`
	LockedUntil          *time.Time `bun:"locked_until" json:"locked_until,omitempty"`
	PasswordChangedAt    *time.Time `bun:"password_changed_at" json:"-"`
	MustChangePassword   bool       `bun:"must_change_password,default:false" json:"must_change_password"`
	LastPasswordResetAt  *time.Time `bun:"last_password_reset_at" json:"-"`
	
	// Role and permissions (for RBAC)
	Role string `bun:"role,default:'user'" json:"role"`
	
	// Platform-agnostic metadata storage
	Metadata Metadata `bun:"metadata,type:jsonb,default:'{}'" json:"metadata,omitempty"`
	
	// Tracking fields
	LastLoginAt *time.Time `bun:"last_login_at" json:"last_login_at,omitempty"`
	IPAddress   *string    `bun:"ip_address" json:"ip_address,omitempty"`
	UserAgent   *string    `bun:"user_agent" json:"-"`
	
	// Timestamps
	CreatedAt time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}

// RefreshToken represents a refresh token in the database
type RefreshToken struct {
	bun.BaseModel `bun:"table:refresh_tokens,alias:rt"`

	ID                 uuid.UUID  `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	UserID             uuid.UUID  `bun:"user_id,notnull" json:"user_id"`
	TokenHash          string     `bun:"token_hash,unique,notnull" json:"-"`
	ExpiresAt          time.Time  `bun:"expires_at,notnull" json:"expires_at"`
	RevokedAt          *time.Time `bun:"revoked_at" json:"revoked_at,omitempty"`
	ReplacedByTokenID  *uuid.UUID `bun:"replaced_by_token_id" json:"replaced_by_token_id,omitempty"`
	CreatedAt          time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	IPAddress          *string    `bun:"ip_address" json:"ip_address,omitempty"`
	UserAgent          *string    `bun:"user_agent" json:"-"`
	DeviceInfo         Metadata   `bun:"device_info,type:jsonb,default:'{}'" json:"device_info,omitempty"`
}

// Session represents a user session in the database
type Session struct {
	bun.BaseModel `bun:"table:sessions,alias:s"`

	ID             uuid.UUID `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	UserID         uuid.UUID `bun:"user_id,notnull" json:"user_id"`
	SessionToken   string    `bun:"session_token,unique,notnull" json:"-"`
	ExpiresAt      time.Time `bun:"expires_at,notnull" json:"expires_at"`
	CreatedAt      time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	LastActivityAt time.Time `bun:"last_activity_at,default:current_timestamp" json:"last_activity_at"`
	IPAddress      *string   `bun:"ip_address" json:"ip_address,omitempty"`
	UserAgent      *string   `bun:"user_agent" json:"-"`
	DeviceInfo     Metadata  `bun:"device_info,type:jsonb,default:'{}'" json:"device_info,omitempty"`
}

// PasswordResetToken represents a password reset token in the database
type PasswordResetToken struct {
	bun.BaseModel `bun:"table:password_reset_tokens,alias:prt"`

	ID        uuid.UUID  `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID  `bun:"user_id,notnull" json:"user_id"`
	TokenHash string     `bun:"token_hash,unique,notnull" json:"-"`
	ExpiresAt time.Time  `bun:"expires_at,notnull" json:"expires_at"`
	UsedAt    *time.Time `bun:"used_at" json:"used_at,omitempty"`
	CreatedAt time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	IPAddress *string    `bun:"ip_address" json:"ip_address,omitempty"`
}

// AuditLog represents an audit log entry in the database
type AuditLog struct {
	bun.BaseModel `bun:"table:audit_logs,alias:al"`

	ID        uuid.UUID  `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	UserID    *uuid.UUID `bun:"user_id" json:"user_id,omitempty"`
	EventType string     `bun:"event_type,notnull" json:"event_type"`
	EventData Metadata   `bun:"event_data,type:jsonb,default:'{}'" json:"event_data,omitempty"`
	IPAddress *string    `bun:"ip_address" json:"ip_address,omitempty"`
	UserAgent *string    `bun:"user_agent" json:"-"`
	CreatedAt time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
}
