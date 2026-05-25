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

// Value implements the driver.Valuer interface for database storage.
// Returns string so PostgreSQL receives valid JSON text for jsonb columns
// (returning []byte would be sent as bytea and rejected by jsonb).
func (m Metadata) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return string(b), nil
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
	PasswordChangedAt    *time.Time `bun:"password_changed_at" json:"-"`
	MustChangePassword   bool       `bun:"must_change_password,default:false" json:"must_change_password"`
	LastPasswordResetAt  *time.Time `bun:"last_password_reset_at" json:"-"`
	
	// Role and permissions (for RBAC)
	Role string `bun:"role,default:'user'" json:"role"`
	
	// Platform-agnostic metadata storage
	Metadata Metadata `bun:"metadata,type:jsonb,default:'{}'" json:"metadata,omitempty"`
	
	// Tracking fields
	LastLoginAt *time.Time `bun:"last_login_at" json:"last_login_at,omitempty"`
	
	// Timestamps
	CreatedAt time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
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

// EmailOutbox represents a row in the transactional outbox for email events.
type EmailOutbox struct {
	bun.BaseModel `bun:"table:email_outbox,alias:eo"`

	ID             uuid.UUID  `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	IdempotencyKey *string    `bun:"idempotency_key,unique" json:"idempotency_key,omitempty"`
	EventType      string     `bun:"event_type,notnull" json:"event_type"`
	Payload        Metadata   `bun:"payload,type:jsonb,notnull" json:"payload"`
	Status         string     `bun:"status,notnull,default:'pending'" json:"status"`
	Attempts       int        `bun:"attempts,notnull,default:0" json:"attempts"`
	LastError      *string    `bun:"last_error" json:"last_error,omitempty"`
	CreatedAt      time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	PublishedAt    *time.Time `bun:"published_at" json:"published_at,omitempty"`
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
