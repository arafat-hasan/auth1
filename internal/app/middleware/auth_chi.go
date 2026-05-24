package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/arafat-hasan/auth1/internal/app/repo"
	"github.com/arafat-hasan/auth1/internal/utils"
	"github.com/sirupsen/logrus"
)

// Authenticate is a Chi middleware that validates JWT tokens
// Now includes JWT blacklist checking for revoked tokens
func Authenticate(jwtManager *utils.JWTManager, redisRepo repo.RedisRepository, logger *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"code":    "AUTH001",
						"message": "Missing authorization header",
					},
				})
				return
			}

			// Check if the header starts with "Bearer "
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"code":    "AUTH001",
						"message": "Invalid authorization header format. Expected: Bearer <token>",
					},
				})
				return
			}

			token := parts[1]

			// Validate token
			claims, err := jwtManager.ValidateAccessToken(token)
			if err != nil {
				if logger != nil {
					logger.WithError(err).WithFields(logrus.Fields{
						"path":   r.URL.Path,
						"method": r.Method,
						"ip":     getClientIP(r),
					}).Warn("Invalid JWT token")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"code":    "AUTH005",
						"message": "Invalid or expired token",
					},
				})
				return
			}

			// 🔒 NEW: Check if JWT is blacklisted (individual token)
			blacklisted, err := redisRepo.IsJWTBlacklisted(r.Context(), claims.ID)
			if err != nil {
				// Fail open on Redis error (allow request but log error)
				if logger != nil {
					logger.WithError(err).WithFields(logrus.Fields{
						"jti":     claims.ID,
						"user_id": claims.UserID,
					}).Error("Failed to check JWT blacklist status - allowing request")
				}
			} else if blacklisted {
				// Token is blacklisted
				if logger != nil {
					logger.WithFields(logrus.Fields{
						"jti":     claims.ID,
						"user_id": claims.UserID,
						"email":   claims.Email,
						"path":    r.URL.Path,
					}).Warn("Attempted use of blacklisted JWT token")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"code":    "AUTH006",
						"message": "Token has been revoked",
					},
				})
				return
			}

			// 🔒 NEW: Check if all user tokens are blacklisted (e.g., password change)
			// This checks if there's a timestamp when all tokens were invalidated
			userIDStr := claims.UserID.String()
			blacklistTimestamp, err := redisRepo.IsUserTokensBlacklisted(r.Context(), userIDStr)
			if err != nil {
				// Fail open on Redis error
				if logger != nil {
					logger.WithError(err).WithField("user_id", claims.UserID).Error("Failed to check user-level blacklist - allowing request")
				}
			} else if blacklistTimestamp > 0 {
				// Check if token was issued before the blacklist timestamp
				tokenIssuedAt := claims.IssuedAt.Unix()
				if tokenIssuedAt < blacklistTimestamp {
					if logger != nil {
						logger.WithFields(logrus.Fields{
							"user_id":             claims.UserID,
							"token_issued_at":     tokenIssuedAt,
							"blacklist_timestamp": blacklistTimestamp,
						}).Warn("Attempted use of token issued before user-level blacklist")
					}

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(w).Encode(map[string]interface{}{
						"error": map[string]interface{}{
							"code":    "AUTH006",
							"message": "Token has been revoked",
						},
					})
					return
				}
			}

			// Add user information to context
			ctx := r.Context()
			ctx = context.WithValue(ctx, "user_id", claims.UserID)
			ctx = context.WithValue(ctx, "email", claims.Email)
			ctx = context.WithValue(ctx, "roles", claims.Roles)
			ctx = context.WithValue(ctx, "jti", claims.ID)                      // Add JTI to context
			ctx = context.WithValue(ctx, "issued_at", claims.IssuedAt.Unix()) // Add issued time

			// Call next handler with updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Helper to get JTI from context
func GetJTIFromContext(ctx context.Context) string {
	if jti, ok := ctx.Value("jti").(string); ok {
		return jti
	}
	return ""
}

// Helper to get issued at timestamp from context
func GetIssuedAtFromContext(ctx context.Context) int64 {
	if issuedAt, ok := ctx.Value("issued_at").(int64); ok {
		return issuedAt
	}
	return 0
}

// Helper to get expiration time from JWT claims
// This will be useful for blacklisting tokens with proper TTL
func GetTokenExpiration(jwtManager *utils.JWTManager, tokenString string) (time.Time, error) {
	claims, err := jwtManager.ValidateAccessToken(tokenString)
	if err != nil {
		return time.Time{}, err
	}
	return claims.ExpiresAt.Time, nil
}
