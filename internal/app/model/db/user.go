package db

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	ID           uuid.UUID  `bun:"id,pk,type:uuid,default:gen_random_uuid()" json:"id"`
	Email        string     `bun:"email,unique,notnull" json:"email"`
	Name         string     `bun:"name,notnull" json:"name"`
	Phone        *string    `bun:"phone,unique" json:"phone,omitempty"`
	PasswordHash *string    `bun:"password_hash" json:"-"`
	IsVerified   bool       `bun:"is_verified,notnull,default:false" json:"is_verified"`
	Is2FAEnabled bool       `bun:"is_2fa_enabled,notnull,default:false" json:"is_2fa_enabled"`
	TOTPSecret   *string    `bun:"totp_secret" json:"-"`
	LastLoginAt  *time.Time `bun:"last_login_at" json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt    time.Time  `bun:"updated_at,nullzero,notnull,default:current_timestamp" json:"updated_at"`
}
