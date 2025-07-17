package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"auth1/internal/app/auth"
	"auth1/internal/app/middleware"
	"auth1/internal/app/model/api"
	"auth1/internal/app/repo"
)

type AuthHandler struct {
	authService  *auth.Service
	userRepo     repo.UserRepository
	logger       *logrus.Logger
	publicKeyPEM string
}

func NewAuthHandler(
	authService *auth.Service,
	userRepo repo.UserRepository,
	logger *logrus.Logger,
	publicKeyPEM string,
) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		userRepo:     userRepo,
		logger:       logger,
		publicKeyPEM: publicKeyPEM,
	}
}

func (h *AuthHandler) Signup(c *gin.Context) {
	var req api.SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
			Success: false,
		})
		return
	}

	err := h.authService.Signup(c.Request.Context(), req.Email, req.Name, req.Phone, req.Password)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"email": req.Email,
			"error": err.Error(),
		}).Error("Signup failed")

		if strings.Contains(err.Error(), "already exists") {
			c.JSON(http.StatusConflict, api.ErrorResponse{
				Error:   "conflict",
				Message: err.Error(),
				Success: false,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, api.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to process signup request",
			Success: false,
		})
		return
	}

	c.JSON(http.StatusAccepted, api.SuccessResponse{
		Message: "OTP sent to your email address",
		Success: true,
	})
}

func (h *AuthHandler) VerifySignup(c *gin.Context) {
	var req api.VerifySignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
			Success: false,
		})
		return
	}

	tokens, err := h.authService.VerifySignup(c.Request.Context(), req.Email, req.OTP)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"email": req.Email,
			"error": err.Error(),
		}).Error("Signup verification failed")

		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired") {
			c.JSON(http.StatusUnauthorized, api.ErrorResponse{
				Error:   "invalid_otp",
				Message: err.Error(),
				Success: false,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, api.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to verify signup",
			Success: false,
		})
		return
	}

	c.JSON(http.StatusOK, api.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
		TokenType:    "Bearer",
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req api.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
			Success: false,
		})
		return
	}

	tokens, user, err := h.authService.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"email": req.Email,
			"error": err.Error(),
		}).Error("Login failed")

		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusUnauthorized, api.ErrorResponse{
				Error:   "invalid_credentials",
				Message: "Invalid email or password",
				Success: false,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, api.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to process login request",
			Success: false,
		})
		return
	}

	// Check if 2FA is required
	if user.Is2FAEnabled && tokens == nil {
		c.JSON(http.StatusOK, api.TwoFactorChallengeResponse{
			RequiresTwoFactor: true,
			Message:           "2FA verification required",
		})
		return
	}

	c.JSON(http.StatusOK, api.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
		TokenType:    "Bearer",
	})
}

func (h *AuthHandler) RequestOTP(c *gin.Context) {
	var req api.RequestOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
			Success: false,
		})
		return
	}

	err := h.authService.RequestOTP(c.Request.Context(), req.Email, req.Purpose)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"email":   req.Email,
			"purpose": req.Purpose,
			"error":   err.Error(),
		}).Error("OTP request failed")

		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, api.ErrorResponse{
				Error:   "user_not_found",
				Message: "User not found",
				Success: false,
			})
			return
		}

		if strings.Contains(err.Error(), "already sent") {
			c.JSON(http.StatusTooManyRequests, api.ErrorResponse{
				Error:   "rate_limit",
				Message: err.Error(),
				Success: false,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, api.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to send OTP",
			Success: false,
		})
		return
	}

	c.JSON(http.StatusOK, api.SuccessResponse{
		Message: "OTP sent successfully",
		Success: true,
	})
}

func (h *AuthHandler) VerifyLogin(c *gin.Context) {
	var req api.VerifyLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
			Success: false,
		})
		return
	}

	tokens, err := h.authService.VerifyLoginOTP(c.Request.Context(), req.Email, req.OTP)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"email": req.Email,
			"error": err.Error(),
		}).Error("Login OTP verification failed")

		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired") {
			c.JSON(http.StatusUnauthorized, api.ErrorResponse{
				Error:   "invalid_otp",
				Message: err.Error(),
				Success: false,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, api.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to verify login OTP",
			Success: false,
		})
		return
	}

	c.JSON(http.StatusOK, api.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
		TokenType:    "Bearer",
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req api.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
			Success: false,
		})
		return
	}

	tokens, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Token refresh failed")

		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "expired") {
			c.JSON(http.StatusUnauthorized, api.ErrorResponse{
				Error:   "invalid_token",
				Message: "Invalid or expired refresh token",
				Success: false,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, api.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to refresh token",
			Success: false,
		})
		return
	}

	c.JSON(http.StatusOK, api.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
		TokenType:    "Bearer",
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req api.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
			Success: false,
		})
		return
	}

	err := h.authService.Logout(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("Logout failed")

		// Even if logout fails, we return success to avoid confusion
		c.JSON(http.StatusOK, api.SuccessResponse{
			Message: "Logged out successfully",
			Success: true,
		})
		return
	}

	c.JSON(http.StatusOK, api.SuccessResponse{
		Message: "Logged out successfully",
		Success: true,
	})
}

func (h *AuthHandler) GetPublicKey(c *gin.Context) {
	c.JSON(http.StatusOK, api.PublicKeyResponse{
		PublicKey: h.publicKeyPEM,
		KeyType:   "RSA",
	})
}

func (h *AuthHandler) GetMe(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, api.ErrorResponse{
			Error:   "unauthorized",
			Message: "User not authenticated",
			Success: false,
		})
		return
	}

	user, err := h.userRepo.GetByID(c.Request.Context(), userID)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("Failed to get user")

		c.JSON(http.StatusInternalServerError, api.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to get user information",
			Success: false,
		})
		return
	}

	if user == nil {
		c.JSON(http.StatusNotFound, api.ErrorResponse{
			Error:   "user_not_found",
			Message: "User not found",
			Success: false,
		})
		return
	}

	c.JSON(http.StatusOK, api.UserResponse{
		ID:           user.ID,
		Email:        user.Email,
		Name:         user.Name,
		IsVerified:   user.IsVerified,
		Is2FAEnabled: user.Is2FAEnabled,
	})
}

func (h *AuthHandler) Setup2FA(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, api.ErrorResponse{
			Error:   "unauthorized",
			Message: "User not authenticated",
			Success: false,
		})
		return
	}

	setupData, err := h.authService.Setup2FA(c.Request.Context(), userID)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("2FA setup failed")

		c.JSON(http.StatusInternalServerError, api.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to setup 2FA",
			Success: false,
		})
		return
	}

	c.JSON(http.StatusOK, api.TwoFactorSetupResponse{
		Secret:    setupData.Secret,
		QRCodeURL: setupData.QRCodeURL,
	})
}

func (h *AuthHandler) Verify2FA(c *gin.Context) {
	var req api.TwoFactorVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, api.ErrorResponse{
			Error:   "validation_error",
			Message: err.Error(),
			Success: false,
		})
		return
	}

	tokens, err := h.authService.Verify2FA(c.Request.Context(), req.UserID, req.TwoFACode)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"user_id": req.UserID,
			"error":   err.Error(),
		}).Error("2FA verification failed")

		if strings.Contains(err.Error(), "invalid") {
			c.JSON(http.StatusUnauthorized, api.ErrorResponse{
				Error:   "invalid_2fa_code",
				Message: "Invalid 2FA code",
				Success: false,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, api.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to verify 2FA",
			Success: false,
		})
		return
	}

	c.JSON(http.StatusOK, api.TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
		TokenType:    "Bearer",
	})
}

func (h *AuthHandler) Disable2FA(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, api.ErrorResponse{
			Error:   "unauthorized",
			Message: "User not authenticated",
			Success: false,
		})
		return
	}

	err := h.authService.Disable2FA(c.Request.Context(), userID)
	if err != nil {
		h.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("2FA disable failed")

		if strings.Contains(err.Error(), "not enabled") {
			c.JSON(http.StatusBadRequest, api.ErrorResponse{
				Error:   "2fa_not_enabled",
				Message: "2FA is not enabled for this user",
				Success: false,
			})
			return
		}

		c.JSON(http.StatusInternalServerError, api.ErrorResponse{
			Error:   "internal_error",
			Message: "Failed to disable 2FA",
			Success: false,
		})
		return
	}

	c.JSON(http.StatusOK, api.SuccessResponse{
		Message: "2FA disabled successfully",
		Success: true,
	})
}
