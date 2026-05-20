package service

import (
	"context"
	"time"

	"github.com/google/uuid"

	"auth1/internal/app/model/domain"
)

// AuthService defines the interface for authentication business logic
type AuthService interface {
	// User registration and verification
	Signup(ctx context.Context, req *SignupRequest) error
	VerifySignup(ctx context.Context, req *VerifySignupRequest) (*domain.TokenPair, error)
	SignupWithPhone(ctx context.Context, req *SignupWithPhoneRequest) error
	VerifyPhoneSignup(ctx context.Context, req *VerifyPhoneSignupRequest) (*domain.TokenPair, error)

	// User authentication
	Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error)
	LoginWithPhone(ctx context.Context, req *LoginWithPhoneRequest) (*LoginResponse, error)
	RequestOTP(ctx context.Context, req *RequestOTPRequest) error
	VerifyLoginOTP(ctx context.Context, req *VerifyLoginRequest) (*domain.TokenPair, error)

	// Password management
	RequestPasswordReset(ctx context.Context, req *PasswordResetRequest) error
	VerifyPasswordResetToken(ctx context.Context, token string) (*domain.User, error)
	ResetPassword(ctx context.Context, req *ResetPasswordRequest) error
	ChangePassword(ctx context.Context, req *ChangePasswordRequest) error

	// Token management
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*domain.TokenPair, error)
	Logout(ctx context.Context, req *LogoutRequest) error
	LogoutAllDevices(ctx context.Context, userID uuid.UUID) error

	// Two-factor authentication
	Setup2FA(ctx context.Context, userID uuid.UUID) (*domain.TOTPSetupData, error)
	Verify2FA(ctx context.Context, req *Verify2FARequest) (*domain.TokenPair, error)
	Disable2FA(ctx context.Context, userID uuid.UUID) error

	// User management
	GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error)
	UpdateUser(ctx context.Context, userID uuid.UUID, req *UpdateUserRequest) error
	DeactivateUser(ctx context.Context, userID uuid.UUID) error
	ReactivateUser(ctx context.Context, userID uuid.UUID) error
	DeleteUser(ctx context.Context, userID uuid.UUID) error // Soft delete
	
	// Account security
	UnlockAccount(ctx context.Context, userID uuid.UUID) error
	
	// Role management
	UpdateUserRole(ctx context.Context, userID uuid.UUID, role string) error
	
	// Metadata management
	UpdateUserMetadata(ctx context.Context, userID uuid.UUID, metadata map[string]interface{}) error
	
	// Public methods
	GetPublicKey() string
}

// Service request/response DTOs

// Signup requests
type SignupRequest struct {
	Email    string                 `json:"email" validate:"required,email"`
	Phone    *string                `json:"phone,omitempty"`
	Password *string                `json:"password,omitempty"`
	Name     string                 `json:"name" validate:"required"`
	Role     string                 `json:"role,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type SignupWithPhoneRequest struct {
	Phone    string                 `json:"phone" validate:"required"`
	Password *string                `json:"password,omitempty"`
	Name     string                 `json:"name" validate:"required"`
	Role     string                 `json:"role,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type VerifySignupRequest struct {
	Email string `json:"email" validate:"required,email"`
	OTP   string `json:"otp" validate:"required,len=6"`
}

type VerifyPhoneSignupRequest struct {
	Phone string `json:"phone" validate:"required"`
	OTP   string `json:"otp" validate:"required,len=6"`
}

// Login requests
type LoginRequest struct {
	Email      string  `json:"email" validate:"required,email"`
	Password   string  `json:"password" validate:"required"`
	IPAddress  *string `json:"-"`
	UserAgent  *string `json:"-"`
	DeviceInfo map[string]interface{} `json:"device_info,omitempty"`
}

type LoginWithPhoneRequest struct {
	Phone      string  `json:"phone" validate:"required"`
	Password   string  `json:"password" validate:"required"`
	IPAddress  *string `json:"-"`
	UserAgent  *string `json:"-"`
	DeviceInfo map[string]interface{} `json:"device_info,omitempty"`
}

type LoginResponse struct {
	Tokens            *domain.TokenPair `json:"tokens,omitempty"`
	User              *domain.User      `json:"user,omitempty"`
	RequiresTwoFactor bool              `json:"requires_two_factor"`
}

// OTP requests
type RequestOTPRequest struct {
	Email   string `json:"email,omitempty"`
	Phone   string `json:"phone,omitempty"`
	Purpose string `json:"purpose" validate:"required,oneof=login signup password_reset"`
}

type VerifyLoginRequest struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
	OTP   string `json:"otp" validate:"required,len=6"`
}

// Password management requests
type PasswordResetRequest struct {
	Email     string `json:"email,omitempty"`
	Phone     string `json:"phone,omitempty"`
	IPAddress *string `json:"-"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required"`
}

type ChangePasswordRequest struct {
	UserID      uuid.UUID `json:"-"`
	OldPassword string    `json:"old_password" validate:"required"`
	NewPassword string    `json:"new_password" validate:"required"`
}

// Token management requests
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// 2FA requests
type Verify2FARequest struct {
	UserID    uuid.UUID `json:"user_id" validate:"required"`
	TwoFACode string    `json:"2fa_code" validate:"required,len=6"`
}

// User management requests
type UpdateUserRequest struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
	Phone *string `json:"phone,omitempty"`
}

// Service configuration
type Config struct {
	OTPLength              int
	OTPTTL                 time.Duration
	PendingUserTTL         time.Duration
	RefreshTokenTTL        time.Duration
	TOTPSecretTTL          time.Duration
	PasswordResetTTL       time.Duration
	PublicKeyPEM           string
	MaxLoginAttempts       int
	LockoutDuration        time.Duration
	
	// Feature flags
	EnableEmailAuth        bool
	EnablePhoneAuth        bool
	EnablePasswordAuth     bool
	EnableOTPAuth          bool
	Enable2FA              bool
	EnableAuditLog         bool
	RequireEmailVerification bool
	RequirePhoneVerification bool
}
