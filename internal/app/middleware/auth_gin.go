package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"auth1/internal/app/model/api"
	"auth1/internal/utils"
)

type AuthMiddleware struct {
	jwtManager *utils.JWTManager
	logger     *logrus.Logger
}

func NewAuthMiddleware(jwtManager *utils.JWTManager, logger *logrus.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager: jwtManager,
		logger:     logger,
	}
}

func (a *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, api.ErrorResponse{
				Error:   "unauthorized",
				Message: "Missing authorization header",
				Success: false,
			})
			c.Abort()
			return
		}

		// Extract bearer token
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, api.ErrorResponse{
				Error:   "unauthorized",
				Message: "Invalid authorization header format",
				Success: false,
			})
			c.Abort()
			return
		}

		tokenString := tokenParts[1]

		// Validate token
		claims, err := a.jwtManager.ValidateAccessToken(tokenString)
		if err != nil {
			a.logger.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("Invalid access token")

			c.JSON(http.StatusUnauthorized, api.ErrorResponse{
				Error:   "unauthorized",
				Message: "Invalid or expired token",
				Success: false,
			})
			c.Abort()
			return
		}

		// Set user context
		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Set("user_roles", claims.Roles)

		c.Next()
	}
}

func (a *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		// Extract bearer token
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
			c.Next()
			return
		}

		tokenString := tokenParts[1]

		// Validate token
		claims, err := a.jwtManager.ValidateAccessToken(tokenString)
		if err != nil {
			// Don't abort, just continue without user context
			c.Next()
			return
		}

		// Set user context
		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Set("user_roles", claims.Roles)

		c.Next()
	}
}

// Helper functions to get user information from context
func GetUserID(c *gin.Context) (uuid.UUID, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, false
	}

	id, ok := userID.(uuid.UUID)
	return id, ok
}

func GetUserEmail(c *gin.Context) (string, bool) {
	userEmail, exists := c.Get("user_email")
	if !exists {
		return "", false
	}

	email, ok := userEmail.(string)
	return email, ok
}

func GetUserRoles(c *gin.Context) ([]string, bool) {
	userRoles, exists := c.Get("user_roles")
	if !exists {
		return nil, false
	}

	roles, ok := userRoles.([]string)
	return roles, ok
}
