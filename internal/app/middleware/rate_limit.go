package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/arafat-hasan/auth1/internal/ratelimit"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RateLimitConfig defines rate limiting configuration
type RateLimitConfig struct {
	Limit   int                                 // Max requests in window
	Window  time.Duration                       // Time window
	KeyFunc func(r *http.Request) string       // Function to generate rate limit key
	Enabled bool                                // Enable/disable rate limiting
	Logger  *logrus.Logger                      // Logger for rate limit events
}

// RateLimit creates a rate limiting middleware
func RateLimit(limiter *ratelimit.RateLimiter, config RateLimitConfig) func(http.Handler) http.Handler {
	// If disabled, return a no-op middleware
	if !config.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Generate rate limit key
			key := config.KeyFunc(r)

			// Check rate limit
			result, err := limiter.Allow(ctx, key, config.Limit, config.Window)
			if err != nil {
				// On Redis error, fail open (allow request) but log error
				if config.Logger != nil {
					config.Logger.WithError(err).WithFields(logrus.Fields{
						"key":       key,
						"endpoint":  r.URL.Path,
						"method":    r.Method,
						"client_ip": getClientIP(r),
					}).Error("Rate limiter error - allowing request (fail open)")
				}

				// Allow request to proceed
				next.ServeHTTP(w, r)
				return
			}

			// Add rate limit headers
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.ResetAt.Unix()))

			if !result.Allowed {
				// Rate limit exceeded
				retryAfter := int(time.Until(result.ResetAt).Seconds())
				if retryAfter < 0 {
					retryAfter = 0
				}

				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)

				// Log rate limit violation
				if config.Logger != nil {
					config.Logger.WithFields(logrus.Fields{
						"key":           key,
						"endpoint":      r.URL.Path,
						"method":        r.Method,
						"client_ip":     getClientIP(r),
						"limit":         result.Limit,
						"window":        config.Window.String(),
						"retry_after":   retryAfter,
						"user_agent":    r.UserAgent(),
					}).Warn("Rate limit exceeded")
				}

				// Return error response
				errorResponse := map[string]interface{}{
					"error": map[string]interface{}{
						"code":                "RATE_LIMIT_EXCEEDED",
						"message":             fmt.Sprintf("Rate limit exceeded. Please try again in %d seconds.", retryAfter),
						"retry_after_seconds": retryAfter,
						"limit":               result.Limit,
						"window":              config.Window.String(),
					},
				}

				json.NewEncoder(w).Encode(errorResponse)
				return
			}

			// Request allowed, proceed
			next.ServeHTTP(w, r)
		})
	}
}

// Key generation functions

// IPBasedKey generates a rate limit key based on client IP
func IPBasedKey(prefix string) func(r *http.Request) string {
	return func(r *http.Request) string {
		ip := getClientIP(r)
		return fmt.Sprintf("ratelimit:%s:ip:%s", prefix, ip)
	}
}

// EmailBasedKey generates a rate limit key based on email from request body
func EmailBasedKey(prefix string) func(r *http.Request) string {
	return func(r *http.Request) string {
		email := extractEmailFromRequest(r)
		if email == "" {
			// Fallback to IP if email not found
			return IPBasedKey(prefix)(r)
		}
		return fmt.Sprintf("ratelimit:%s:email:%s", prefix, email)
	}
}

// UserBasedKey generates a rate limit key based on authenticated user ID
func UserBasedKey(prefix string) func(r *http.Request) string {
	return func(r *http.Request) string {
		userID := getUserIDFromContext(r.Context())
		if userID == uuid.Nil {
			// Fallback to IP if user not authenticated
			return IPBasedKey(prefix)(r)
		}
		return fmt.Sprintf("ratelimit:%s:user:%s", prefix, userID.String())
	}
}

// CompositeKey generates a rate limit key combining IP and email
func CompositeKey(prefix string) func(r *http.Request) string {
	return func(r *http.Request) string {
		ip := getClientIP(r)
		email := extractEmailFromRequest(r)
		if email == "" {
			return fmt.Sprintf("ratelimit:%s:ip:%s", prefix, ip)
		}
		return fmt.Sprintf("ratelimit:%s:ip:%s:email:%s", prefix, ip, email)
	}
}

// TokenBasedKey generates a rate limit key based on token or refresh token
func TokenBasedKey(prefix string) func(r *http.Request) string {
	return func(r *http.Request) string {
		token := extractTokenFromRequest(r)
		if token == "" {
			return IPBasedKey(prefix)(r)
		}
		// Hash token to avoid storing full token in Redis
		tokenHash := fmt.Sprintf("%x", token[:min(len(token), 16)])
		return fmt.Sprintf("ratelimit:%s:token:%s", prefix, tokenHash)
	}
}

// PathParamKey generates a rate limit key based on URL path parameter
func PathParamKey(prefix, paramName string) func(r *http.Request) string {
	return func(r *http.Request) string {
		paramValue := chi.URLParam(r, paramName)
		if paramValue == "" {
			return IPBasedKey(prefix)(r)
		}
		return fmt.Sprintf("ratelimit:%s:%s:%s", prefix, paramName, paramValue)
	}
}

// Helper functions

// GetClientIP extracts the real client IP address (exported for use by handlers)
func GetClientIP(r *http.Request) string {
	return getClientIP(r)
}

// getClientIP extracts the real client IP address
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (from load balancer/proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take first IP (client IP)
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// extractEmailFromRequest parses the request body to extract email
func extractEmailFromRequest(r *http.Request) string {
	// Only process JSON requests
	if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return ""
	}

	// Read body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}

	// Restore body for next handler
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Parse JSON
	var body map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		return ""
	}

	// Restore body again after parsing
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Extract email
	if email, ok := body["email"].(string); ok {
		return strings.ToLower(strings.TrimSpace(email))
	}

	return ""
}

// extractTokenFromRequest extracts token from request body or header
func extractTokenFromRequest(r *http.Request) string {
	// Check Authorization header
	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// Check request body for refresh_token
	if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return ""
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return ""
	}

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var body map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		return ""
	}

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if token, ok := body["refresh_token"].(string); ok {
		return token
	}

	return ""
}

// getUserIDFromContext extracts user ID from context (set by auth middleware)
func getUserIDFromContext(ctx interface{}) uuid.UUID {
	// Try to get user_id from context
	type contextKey string
	const userIDKey contextKey = "user_id"

	if userID, ok := ctx.(interface{ Value(interface{}) interface{} }).Value(userIDKey).(uuid.UUID); ok {
		return userID
	}

	// Also try string format
	if userIDStr, ok := ctx.(interface{ Value(interface{}) interface{} }).Value(userIDKey).(string); ok {
		if userID, err := uuid.Parse(userIDStr); err == nil {
			return userID
		}
	}

	return uuid.Nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MultiKeyRateLimit applies multiple rate limits (all must pass)
// Example: Rate limit by both IP and email
func MultiKeyRateLimit(limiter *ratelimit.RateLimiter, configs []RateLimitConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Check all rate limits
			for i, config := range configs {
				if !config.Enabled {
					continue
				}

				key := config.KeyFunc(r)
				result, err := limiter.Allow(ctx, key, config.Limit, config.Window)

				if err != nil {
					if config.Logger != nil {
						config.Logger.WithError(err).WithFields(logrus.Fields{
							"key":       key,
							"config_idx": i,
						}).Error("Rate limiter error - allowing request")
					}
					continue // Fail open
				}

				// Add headers from first config
				if i == 0 {
					w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
					w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
					w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.ResetAt.Unix()))
				}

				if !result.Allowed {
					retryAfter := int(time.Until(result.ResetAt).Seconds())
					if retryAfter < 0 {
						retryAfter = 0
					}

					w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)

					if config.Logger != nil {
						config.Logger.WithFields(logrus.Fields{
							"key":         key,
							"endpoint":    r.URL.Path,
							"config_idx":  i,
							"limit":       result.Limit,
							"window":      config.Window.String(),
						}).Warn("Rate limit exceeded (multi-key)")
					}

					errorResponse := map[string]interface{}{
						"error": map[string]interface{}{
							"code":                "RATE_LIMIT_EXCEEDED",
							"message":             fmt.Sprintf("Rate limit exceeded. Please try again in %d seconds.", retryAfter),
							"retry_after_seconds": retryAfter,
							"limit":               result.Limit,
							"window":              config.Window.String(),
						},
					}

					json.NewEncoder(w).Encode(errorResponse)
					return
				}
			}

			// All rate limits passed
			next.ServeHTTP(w, r)
		})
	}
}
