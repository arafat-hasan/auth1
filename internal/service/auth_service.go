package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app/model/domain"
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
	// Confirm2FASetup validates TOTP code against temp Redis secret and persists it to DB.
	// Called after Setup2FA from an authenticated session. Does NOT issue tokens.
	Confirm2FASetup(ctx context.Context, req *Confirm2FASetupRequest) error
	// Verify2FALogin validates a challenge token (from Login 202) + TOTP code and issues JWT tokens.
	Verify2FALogin(ctx context.Context, req *Verify2FALoginRequest) (*domain.TokenPair, error)
	Disable2FA(ctx context.Context, userID uuid.UUID) error

	// User management
	GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error)
	ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error)
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

	// Session management
	ListUserSessions(ctx context.Context, userID uuid.UUID) ([]domain.SessionInfo, error)
	RevokeUserSession(ctx context.Context, userID uuid.UUID, jti string) error

	// Audit logging (called from handlers with full actor context)
	AuditAdminAction(ctx context.Context, adminID uuid.UUID, eventType string, data map[string]interface{}, ip string)

	// Public key for token verification
	GetPublicKey() string
}
