package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/model/domain"
)

// AuthService defines the interface for authentication business logic.
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
	DeleteUser(ctx context.Context, userID uuid.UUID) error

	// Account security
	UnlockAccount(ctx context.Context, userID uuid.UUID) error

	// Role management
	UpdateUserRole(ctx context.Context, userID uuid.UUID, role string) error

	// Metadata management
	UpdateUserMetadata(ctx context.Context, userID uuid.UUID, metadata map[string]interface{}) error

	// Public key for token verification
	GetPublicKey() string
}
