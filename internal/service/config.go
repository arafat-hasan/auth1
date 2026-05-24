package service

import "time"

// Config holds all tunable parameters for the AuthService.
type Config struct {
	OTPLength        int
	OTPTTL           time.Duration
	PendingUserTTL   time.Duration
	RefreshTokenTTL  time.Duration
	TOTPSecretTTL    time.Duration
	TOTPChallengeTTL time.Duration
	PasswordResetTTL time.Duration
	PublicKeyPEM     string
	MaxLoginAttempts int
	LockoutDuration  time.Duration

	// AES-256 key for encrypting TOTP secrets at rest (32 bytes, decoded from config)
	TOTPEncryptionKey []byte

	// Feature flags
	EnableEmailAuth          bool
	EnablePhoneAuth          bool
	EnablePasswordAuth       bool
	EnableOTPAuth            bool
	Enable2FA                bool
	EnableAuditLog           bool
	RequireEmailVerification bool
	RequirePhoneVerification bool
}
