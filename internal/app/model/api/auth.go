package api

import "github.com/google/uuid"

// Request Types with OpenAPI annotations

// SignupRequest represents the signup request payload
// @Description User signup request
type SignupRequest struct {
	Email    string  `json:"email" binding:"required,email" example:"user@example.com"`
	Phone    *string `json:"phone,omitempty" example:"+1234567890"`
	Password *string `json:"password,omitempty" example:"securePassword123"`
	Name     string  `json:"name" binding:"required" example:"John Doe"`
}

// VerifySignupRequest represents the signup verification request payload
// @Description Verify signup OTP request
type VerifySignupRequest struct {
	Email string `json:"email" binding:"required,email" example:"user@example.com"`
	OTP   string `json:"otp" binding:"required,len=6" example:"123456"`
}

// LoginRequest represents the login request payload
// @Description User login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email" example:"user@example.com"`
	Password string `json:"password" binding:"required" example:"securePassword123"`
}

// RequestOTPRequest represents the OTP request payload
// @Description Request OTP for login or signup
type RequestOTPRequest struct {
	Email   string `json:"email" binding:"required,email" example:"user@example.com"`
	Purpose string `json:"purpose" binding:"required,oneof=login signup" example:"login"`
}

// VerifyLoginRequest represents the login verification request payload
// @Description Verify login OTP request
type VerifyLoginRequest struct {
	Email string `json:"email" binding:"required,email" example:"user@example.com"`
	OTP   string `json:"otp" binding:"required,len=6" example:"123456"`
}

// RefreshTokenRequest represents the refresh token request payload
// @Description Refresh access token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required" example:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// LogoutRequest represents the logout request payload
// @Description Logout request
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required" example:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// TwoFactorVerifyRequest represents the 2FA verification request payload
// @Description Verify 2FA code request
type TwoFactorVerifyRequest struct {
	UserID    uuid.UUID `json:"user_id" binding:"required" example:"550e8400-e29b-41d4-a716-446655440000"`
	TwoFACode string    `json:"2fa_code" binding:"required,len=6" example:"123456"`
}

// Response Types

// TokenResponse represents the token response
// @Description JWT token response
type TokenResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."`
	ExpiresIn    int    `json:"expires_in" example:"900"`
	TokenType    string `json:"token_type" example:"Bearer"`
}

// UserResponse represents the user response
// @Description User information response
type UserResponse struct {
	ID           uuid.UUID `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Email        string    `json:"email" example:"user@example.com"`
	Name         string    `json:"name" example:"John Doe"`
	IsVerified   bool      `json:"is_verified" example:"true"`
	Is2FAEnabled bool      `json:"is_2fa_enabled" example:"false"`
}

// TwoFactorSetupResponse represents the 2FA setup response
// @Description 2FA setup response with secret and QR code
type TwoFactorSetupResponse struct {
	Secret    string `json:"secret" example:"JBSWY3DPEHPK3PXP"`
	QRCodeURL string `json:"qr_code_url" example:"otpauth://totp/auth1:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=auth1"`
}

// PublicKeyResponse represents the public key response
// @Description JWT public key response
type PublicKeyResponse struct {
	PublicKey string `json:"public_key" example:"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEF..."`
	KeyType   string `json:"key_type" example:"RSA"`
}

// SuccessResponse represents a generic success response
// @Description Generic success response
type SuccessResponse struct {
	Message string `json:"message" example:"Operation completed successfully"`
	Success bool   `json:"success" example:"true"`
}

// ErrorResponse represents an error response
// @Description Error response
type ErrorResponse struct {
	Error   string `json:"error" example:"validation_error"`
	Message string `json:"message" example:"Invalid input data"`
	Success bool   `json:"success" example:"false"`
}

// TwoFactorChallengeResponse represents the 2FA challenge response
// @Description 2FA challenge response
type TwoFactorChallengeResponse struct {
	RequiresTwoFactor bool       `json:"requires_two_factor" example:"true"`
	Message           string     `json:"message" example:"2FA verification required"`
	UserID            *uuid.UUID `json:"user_id,omitempty" example:"550e8400-e29b-41d4-a716-446655440000"`
}

// HealthResponse represents the health check response
// @Description Health check response
type HealthResponse struct {
	Status  string `json:"status" example:"healthy"`
	Service string `json:"service" example:"auth1"`
	Version string `json:"version" example:"1.0.0"`
}
