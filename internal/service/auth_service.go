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

	// User authentication
	Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error)
	RequestOTP(ctx context.Context, req *RequestOTPRequest) error
	VerifyLoginOTP(ctx context.Context, req *VerifyLoginRequest) (*domain.TokenPair, error)

	// Token management
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*domain.TokenPair, error)
	Logout(ctx context.Context, req *LogoutRequest) error

	// Two-factor authentication
	Setup2FA(ctx context.Context, userID uuid.UUID) (*domain.TOTPSetupData, error)
	Verify2FA(ctx context.Context, req *Verify2FARequest) (*domain.TokenPair, error)
	Disable2FA(ctx context.Context, userID uuid.UUID) error

	// User management
	GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error)
	GetPublicKey() string
}

// Service request/response DTOs
type SignupRequest struct {
	Email    string  `json:"email" validate:"required,email"`
	Phone    *string `json:"phone,omitempty"`
	Password *string `json:"password,omitempty"`
	Name     string  `json:"name" validate:"required"`
}

type VerifySignupRequest struct {
	Email string `json:"email" validate:"required,email"`
	OTP   string `json:"otp" validate:"required,len=6"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	Tokens            *domain.TokenPair `json:"tokens,omitempty"`
	User              *domain.User      `json:"user,omitempty"`
	RequiresTwoFactor bool              `json:"requires_two_factor"`
}

type RequestOTPRequest struct {
	Email   string `json:"email" validate:"required,email"`
	Purpose string `json:"purpose" validate:"required,oneof=login signup"`
}

type VerifyLoginRequest struct {
	Email string `json:"email" validate:"required,email"`
	OTP   string `json:"otp" validate:"required,len=6"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type Verify2FARequest struct {
	UserID    uuid.UUID `json:"user_id" validate:"required"`
	TwoFACode string    `json:"2fa_code" validate:"required,len=6"`
}

// Service configuration
type Config struct {
	OTPLength       int
	OTPTTL          time.Duration
	PendingUserTTL  time.Duration
	RefreshTokenTTL time.Duration
	TOTPSecretTTL   time.Duration
	PublicKeyPEM    string
}
