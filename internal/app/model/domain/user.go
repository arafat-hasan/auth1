package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID           uuid.UUID  `json:"id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	Phone        *string    `json:"phone,omitempty"`
	PasswordHash *string    `json:"-"`
	IsVerified   bool       `json:"is_verified"`
	Is2FAEnabled bool       `json:"is_2fa_enabled"`
	TOTPSecret   *string    `json:"-"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type PendingUser struct {
	Email     string    `json:"email"`
	Phone     *string   `json:"phone,omitempty"`
	Password  *string   `json:"-"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
}

type OTPData struct {
	HashedOTP string    `json:"-"`
	Purpose   string    `json:"purpose"`
	ExpiresAt time.Time `json:"expires_at"`
	Email     string    `json:"email"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type RefreshTokenData struct {
	UserID    uuid.UUID `json:"user_id"`
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TOTPSetupData struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
}
