package service

import (
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app/model/domain"
)

// --- Registration ---

type SignupRequest struct {
	Email    string                 `json:"email"    validate:"required,email"`
	Phone    *string                `json:"phone,omitempty"`
	Password *string                `json:"password,omitempty"`
	Name     string                 `json:"name"     validate:"required"`
	Role     string                 `json:"role,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type SignupWithPhoneRequest struct {
	Phone    string                 `json:"phone"    validate:"required"`
	Password *string                `json:"password,omitempty"`
	Name     string                 `json:"name"     validate:"required"`
	Role     string                 `json:"role,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type VerifySignupRequest struct {
	Email     string  `json:"email" validate:"required,email"`
	OTP       string  `json:"otp"   validate:"required,len=6"`
	IPAddress *string `json:"-"`
	UserAgent *string `json:"-"`
}

type VerifyPhoneSignupRequest struct {
	Phone     string  `json:"phone" validate:"required"`
	OTP       string  `json:"otp"   validate:"required,len=6"`
	IPAddress *string `json:"-"`
	UserAgent *string `json:"-"`
}

// --- Login ---

type LoginRequest struct {
	Email      string                 `json:"email"    validate:"required,email"`
	Password   string                 `json:"password" validate:"required"`
	IPAddress  *string                `json:"-"`
	UserAgent  *string                `json:"-"`
	DeviceInfo map[string]interface{} `json:"device_info,omitempty"`
}

type LoginWithPhoneRequest struct {
	Phone      string                 `json:"phone"    validate:"required"`
	Password   string                 `json:"password" validate:"required"`
	IPAddress  *string                `json:"-"`
	UserAgent  *string                `json:"-"`
	DeviceInfo map[string]interface{} `json:"device_info,omitempty"`
}

type LoginResponse struct {
	Tokens            *domain.TokenPair `json:"tokens,omitempty"`
	User              *domain.User      `json:"user,omitempty"`
	RequiresTwoFactor bool              `json:"requires_two_factor"`
	ChallengeToken    string            `json:"challenge_token,omitempty"`
}

// --- OTP ---

type RequestOTPRequest struct {
	Email   string `json:"email,omitempty"`
	Phone   string `json:"phone,omitempty"`
	Purpose string `json:"purpose" validate:"required,oneof=login signup password_reset"`
}

type VerifyLoginRequest struct {
	Email     string  `json:"email,omitempty"`
	Phone     string  `json:"phone,omitempty"`
	OTP       string  `json:"otp" validate:"required,len=6"`
	IPAddress *string `json:"-"`
	UserAgent *string `json:"-"`
}

// --- Password management ---

type PasswordResetRequest struct {
	Email     string  `json:"email,omitempty"`
	Phone     string  `json:"phone,omitempty"`
	IPAddress *string `json:"-"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"        validate:"required"`
	NewPassword string `json:"new_password" validate:"required"`
}

type ChangePasswordRequest struct {
	UserID      uuid.UUID `json:"-"`
	OldPassword string    `json:"old_password" validate:"required"`
	NewPassword string    `json:"new_password" validate:"required"`
}

// --- Token management ---

type RefreshTokenRequest struct {
	RefreshToken string  `json:"refresh_token" validate:"required"`
	IPAddress    *string `json:"-"`
	UserAgent    *string `json:"-"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// --- Two-factor authentication ---

// Verify2FALoginRequest is used to complete login after a 2FA challenge is issued.
// The ChallengeToken was returned in the 202 response from Login.
type Verify2FALoginRequest struct {
	ChallengeToken string  `json:"challenge_token" validate:"required"`
	TwoFACode      string  `json:"two_fa_code"     validate:"required,len=6"`
	IPAddress      *string `json:"-"`
	UserAgent      *string `json:"-"`
}

// Confirm2FASetupRequest confirms TOTP setup. UserID is set from the JWT, not request body.
type Confirm2FASetupRequest struct {
	UserID    uuid.UUID `json:"-"`
	TwoFACode string    `json:"two_fa_code" validate:"required,len=6"`
}

// --- User management ---

type UpdateUserRequest struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
	Phone *string `json:"phone,omitempty"`
}

type ListUsersRequest struct {
	Page     int
	PageSize int
	Search   string
	Role     string
	IsActive *bool
}

type ListUsersResponse struct {
	Users      []*domain.User
	Total      int
	Page       int
	PageSize   int
	TotalPages int
}
