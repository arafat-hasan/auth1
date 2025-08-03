package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"auth1/internal/app/model/api"
	"auth1/internal/service"
	"auth1/internal/utils"
)

// AuthHandler handles authentication HTTP requests
type AuthHandler struct {
	authService service.AuthService
	jwtManager  *utils.JWTManager
	validator   *validator.Validate
	logger      *logrus.Logger
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(authService service.AuthService, jwtManager *utils.JWTManager, logger *logrus.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		jwtManager:  jwtManager,
		validator:   validator.New(),
		logger:      logger,
	}
}

// RegisterRoutes registers authentication routes
func (h *AuthHandler) RegisterRoutes(r chi.Router) {
	r.Route("/auth", func(r chi.Router) {
		// Public routes
		r.Post("/signup", h.Signup)
		r.Post("/verify-signup", h.VerifySignup)
		r.Post("/login", h.Login)
		r.Post("/request-otp", h.RequestOTP)
		r.Post("/verify-login", h.VerifyLogin)
		r.Post("/refresh", h.RefreshToken)
		r.Post("/logout", h.Logout)
		r.Get("/public-key", h.GetPublicKey)
		r.Post("/2fa/verify", h.Verify2FA)

		// Protected routes
		r.Group(func(r chi.Router) {
			r.Use(h.requireAuth)
			r.Get("/me", h.GetMe)
			r.Post("/2fa/setup", h.Setup2FA)
			r.Post("/2fa/disable", h.Disable2FA)
		})
	})
}

// Signup handles user signup
// @Summary User signup
// @Description Register a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param request body api.SignupRequest true "Signup request"
// @Success 202 {object} api.SuccessResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 409 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/signup [post]
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var req api.SignupRequest
	if err := h.decodeAndValidate(r, &req); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	serviceReq := &service.SignupRequest{
		Email:    req.Email,
		Phone:    req.Phone,
		Password: req.Password,
		Name:     req.Name,
	}

	if err := h.authService.Signup(r.Context(), serviceReq); err != nil {
		h.logger.WithFields(logrus.Fields{
			"email": req.Email,
			"error": err.Error(),
		}).Error("Signup failed")

		if strings.Contains(err.Error(), "already exists") {
			h.renderError(w, r, http.StatusConflict, "conflict", err.Error())
			return
		}

		h.renderError(w, r, http.StatusInternalServerError, "internal_error", "Failed to process signup request")
		return
	}

	h.renderSuccess(w, r, http.StatusAccepted, "OTP sent to your email address")
}

// VerifySignup handles signup verification
// @Summary Verify signup
// @Description Verify signup with OTP and complete user registration
// @Tags auth
// @Accept json
// @Produce json
// @Param request body api.VerifySignupRequest true "Verify signup request"
// @Success 200 {object} api.TokenResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/verify-signup [post]
func (h *AuthHandler) VerifySignup(w http.ResponseWriter, r *http.Request) {
	var req api.VerifySignupRequest
	if err := h.decodeAndValidate(r, &req); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	serviceReq := &service.VerifySignupRequest{
		Email: req.Email,
		OTP:   req.OTP,
	}

	tokens, err := h.authService.VerifySignup(r.Context(), serviceReq)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"email": req.Email,
			"error": err.Error(),
		}).Error("Signup verification failed")

		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired") {
			h.renderError(w, r, http.StatusUnauthorized, "invalid_otp", err.Error())
			return
		}

		h.renderError(w, r, http.StatusInternalServerError, "internal_error", "Failed to verify signup")
		return
	}

	response := &api.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
		TokenType:    "Bearer",
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// Login handles user login
// @Summary User login
// @Description Authenticate user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body api.LoginRequest true "Login request"
// @Success 200 {object} api.TokenResponse
// @Success 200 {object} api.TwoFactorChallengeResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req api.LoginRequest
	if err := h.decodeAndValidate(r, &req); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	serviceReq := &service.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	loginResp, err := h.authService.Login(r.Context(), serviceReq)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"email": req.Email,
			"error": err.Error(),
		}).Error("Login failed")

		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "not found") {
			h.renderError(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
			return
		}

		h.renderError(w, r, http.StatusInternalServerError, "internal_error", "Failed to process login request")
		return
	}

	// Check if 2FA is required
	if loginResp.RequiresTwoFactor {
		response := &api.TwoFactorChallengeResponse{
			RequiresTwoFactor: true,
			Message:           "2FA verification required",
			UserID:            &loginResp.User.ID,
		}
		render.Status(r, http.StatusOK)
		render.JSON(w, r, response)
		return
	}

	response := &api.TokenResponse{
		AccessToken:  loginResp.Tokens.AccessToken,
		RefreshToken: loginResp.Tokens.RefreshToken,
		ExpiresIn:    loginResp.Tokens.ExpiresIn,
		TokenType:    "Bearer",
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// RequestOTP handles OTP requests
// @Summary Request OTP
// @Description Request OTP for login or signup verification
// @Tags auth
// @Accept json
// @Produce json
// @Param request body api.RequestOTPRequest true "Request OTP"
// @Success 200 {object} api.SuccessResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 404 {object} api.ErrorResponse
// @Failure 429 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/request-otp [post]
func (h *AuthHandler) RequestOTP(w http.ResponseWriter, r *http.Request) {
	var req api.RequestOTPRequest
	if err := h.decodeAndValidate(r, &req); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	serviceReq := &service.RequestOTPRequest{
		Email:   req.Email,
		Purpose: req.Purpose,
	}

	if err := h.authService.RequestOTP(r.Context(), serviceReq); err != nil {
		h.logger.WithFields(logrus.Fields{
			"email":   req.Email,
			"purpose": req.Purpose,
			"error":   err.Error(),
		}).Error("OTP request failed")

		if strings.Contains(err.Error(), "not found") {
			h.renderError(w, r, http.StatusNotFound, "user_not_found", "User not found")
			return
		}

		if strings.Contains(err.Error(), "already sent") {
			h.renderError(w, r, http.StatusTooManyRequests, "rate_limit", err.Error())
			return
		}

		h.renderError(w, r, http.StatusInternalServerError, "internal_error", "Failed to send OTP")
		return
	}

	h.renderSuccess(w, r, http.StatusOK, "OTP sent successfully")
}

// VerifyLogin handles login OTP verification
// @Summary Verify login OTP
// @Description Verify login with OTP
// @Tags auth
// @Accept json
// @Produce json
// @Param request body api.VerifyLoginRequest true "Verify login request"
// @Success 200 {object} api.TokenResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/verify-login [post]
func (h *AuthHandler) VerifyLogin(w http.ResponseWriter, r *http.Request) {
	var req api.VerifyLoginRequest
	if err := h.decodeAndValidate(r, &req); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	serviceReq := &service.VerifyLoginRequest{
		Email: req.Email,
		OTP:   req.OTP,
	}

	tokens, err := h.authService.VerifyLoginOTP(r.Context(), serviceReq)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"email": req.Email,
			"error": err.Error(),
		}).Error("Login OTP verification failed")

		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired") {
			h.renderError(w, r, http.StatusUnauthorized, "invalid_otp", err.Error())
			return
		}

		h.renderError(w, r, http.StatusInternalServerError, "internal_error", "Failed to verify login OTP")
		return
	}

	response := &api.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
		TokenType:    "Bearer",
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// RefreshToken handles token refresh
// @Summary Refresh token
// @Description Refresh access token using refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body api.RefreshTokenRequest true "Refresh token request"
// @Success 200 {object} api.TokenResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req api.RefreshTokenRequest
	if err := h.decodeAndValidate(r, &req); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	serviceReq := &service.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	}

	tokens, err := h.authService.RefreshToken(r.Context(), serviceReq)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Token refresh failed")

		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired") {
			h.renderError(w, r, http.StatusUnauthorized, "invalid_token", "Invalid or expired refresh token")
			return
		}

		h.renderError(w, r, http.StatusInternalServerError, "internal_error", "Failed to refresh token")
		return
	}

	response := &api.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
		TokenType:    "Bearer",
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// Logout handles user logout
// @Summary User logout
// @Description Logout user and invalidate refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body api.LogoutRequest true "Logout request"
// @Success 200 {object} api.SuccessResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req api.LogoutRequest
	if err := h.decodeAndValidate(r, &req); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	serviceReq := &service.LogoutRequest{
		RefreshToken: req.RefreshToken,
	}

	if err := h.authService.Logout(r.Context(), serviceReq); err != nil {
		h.logger.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Logout failed")

		// Even if logout fails, we return success to avoid confusion
		h.renderSuccess(w, r, http.StatusOK, "Logged out successfully")
		return
	}

	h.renderSuccess(w, r, http.StatusOK, "Logged out successfully")
}

// GetPublicKey handles public key retrieval
// @Summary Get public key
// @Description Get JWT public key for token verification
// @Tags auth
// @Produce json
// @Success 200 {object} api.PublicKeyResponse
// @Router /auth/public-key [get]
func (h *AuthHandler) GetPublicKey(w http.ResponseWriter, r *http.Request) {
	publicKey := h.authService.GetPublicKey()
	response := &api.PublicKeyResponse{
		PublicKey: publicKey,
		KeyType:   "RSA",
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// GetMe handles user profile retrieval
// @Summary Get user profile
// @Description Get current user information
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} api.UserResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 404 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/me [get]
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == uuid.Nil {
		h.renderError(w, r, http.StatusUnauthorized, "unauthorized", "User not authenticated")
		return
	}

	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("Failed to get user")

		h.renderError(w, r, http.StatusInternalServerError, "internal_error", "Failed to get user information")
		return
	}

	if user == nil {
		h.renderError(w, r, http.StatusNotFound, "user_not_found", "User not found")
		return
	}

	response := &api.UserResponse{
		ID:           user.ID,
		Email:        user.Email,
		Name:         user.Name,
		IsVerified:   user.IsVerified,
		Is2FAEnabled: user.Is2FAEnabled,
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// Setup2FA handles 2FA setup
// @Summary Setup 2FA
// @Description Setup two-factor authentication for user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} api.TwoFactorSetupResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/2fa/setup [post]
func (h *AuthHandler) Setup2FA(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == uuid.Nil {
		h.renderError(w, r, http.StatusUnauthorized, "unauthorized", "User not authenticated")
		return
	}

	setupData, err := h.authService.Setup2FA(r.Context(), userID)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("2FA setup failed")

		h.renderError(w, r, http.StatusInternalServerError, "internal_error", "Failed to setup 2FA")
		return
	}

	response := &api.TwoFactorSetupResponse{
		Secret:    setupData.Secret,
		QRCodeURL: setupData.QRCodeURL,
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// Verify2FA handles 2FA verification
// @Summary Verify 2FA
// @Description Verify two-factor authentication code
// @Tags auth
// @Accept json
// @Produce json
// @Param request body api.TwoFactorVerifyRequest true "2FA verify request"
// @Success 200 {object} api.TokenResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/2fa/verify [post]
func (h *AuthHandler) Verify2FA(w http.ResponseWriter, r *http.Request) {
	var req api.TwoFactorVerifyRequest
	if err := h.decodeAndValidate(r, &req); err != nil {
		h.renderError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	serviceReq := &service.Verify2FARequest{
		UserID:    req.UserID,
		TwoFACode: req.TwoFACode,
	}

	tokens, err := h.authService.Verify2FA(r.Context(), serviceReq)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"user_id": req.UserID,
			"error":   err.Error(),
		}).Error("2FA verification failed")

		if strings.Contains(err.Error(), "invalid") {
			h.renderError(w, r, http.StatusUnauthorized, "invalid_2fa_code", "Invalid 2FA code")
			return
		}

		h.renderError(w, r, http.StatusInternalServerError, "internal_error", "Failed to verify 2FA")
		return
	}

	response := &api.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
		TokenType:    "Bearer",
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, response)
}

// Disable2FA handles 2FA disabling
// @Summary Disable 2FA
// @Description Disable two-factor authentication for user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} api.SuccessResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 401 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /auth/2fa/disable [post]
func (h *AuthHandler) Disable2FA(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == uuid.Nil {
		h.renderError(w, r, http.StatusUnauthorized, "unauthorized", "User not authenticated")
		return
	}

	if err := h.authService.Disable2FA(r.Context(), userID); err != nil {
		h.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("2FA disable failed")

		if strings.Contains(err.Error(), "not enabled") {
			h.renderError(w, r, http.StatusBadRequest, "2fa_not_enabled", "2FA is not enabled for this user")
			return
		}

		h.renderError(w, r, http.StatusInternalServerError, "internal_error", "Failed to disable 2FA")
		return
	}

	h.renderSuccess(w, r, http.StatusOK, "2FA disabled successfully")
}

// Helper methods

func (h *AuthHandler) decodeAndValidate(r *http.Request, v interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return err
	}
	return h.validator.Struct(v)
}

func (h *AuthHandler) renderError(w http.ResponseWriter, r *http.Request, status int, errorType, message string) {
	render.Status(r, status)
	render.JSON(w, r, &api.ErrorResponse{
		Error:   errorType,
		Message: message,
		Success: false,
	})
}

func (h *AuthHandler) renderSuccess(w http.ResponseWriter, r *http.Request, status int, message string) {
	render.Status(r, status)
	render.JSON(w, r, &api.SuccessResponse{
		Message: message,
		Success: true,
	})
}

func (h *AuthHandler) getUserID(r *http.Request) uuid.UUID {
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return userID
}

func (h *AuthHandler) getUserEmail(r *http.Request) string {
	email, ok := r.Context().Value("user_email").(string)
	if !ok {
		return ""
	}
	return email
}

// requireAuth middleware for protected routes
func (h *AuthHandler) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.renderError(w, r, http.StatusUnauthorized, "unauthorized", "Missing authorization header")
			return
		}

		// Extract bearer token
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
			h.renderError(w, r, http.StatusUnauthorized, "unauthorized", "Invalid authorization header format")
			return
		}

		tokenString := tokenParts[1]

		// Validate token
		claims, err := h.jwtManager.ValidateAccessToken(tokenString)
		if err != nil {
			h.logger.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("Invalid access token")

			h.renderError(w, r, http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
			return
		}

		// Set user context
		ctx := context.WithValue(r.Context(), "user_id", claims.UserID)
		ctx = context.WithValue(ctx, "user_email", claims.Email)
		ctx = context.WithValue(ctx, "user_roles", claims.Roles)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
