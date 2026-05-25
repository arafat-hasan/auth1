package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// RequireServiceAPIKey validates the Authorization: ApiKey <key> header against
// the configured list of allowed service keys.  Used to protect internal
// service-to-service endpoints such as /api/v1/auth/introspect.
func RequireServiceAPIKey(allowedKeys []string, logger *logrus.Logger) func(http.Handler) http.Handler {
	keySet := make(map[string]struct{}, len(allowedKeys))
	for _, k := range allowedKeys {
		if k != "" {
			keySet[k] = struct{}{}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeAPIKeyError(w, http.StatusUnauthorized, "SERVICE001", "Missing Authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "ApiKey") {
				writeAPIKeyError(w, http.StatusUnauthorized, "SERVICE001", "Invalid format, expected: ApiKey <key>")
				return
			}

			if len(keySet) == 0 {
				if logger != nil {
					logger.WithField("ip", getClientIP(r)).Warn("Introspect called but no service API keys configured")
				}
				writeAPIKeyError(w, http.StatusServiceUnavailable, "SERVICE003", "Service authentication not configured")
				return
			}

			if _, ok := keySet[parts[1]]; !ok {
				if logger != nil {
					logger.WithFields(logrus.Fields{
						"ip":   getClientIP(r),
						"path": r.URL.Path,
					}).Warn("Invalid service API key")
				}
				writeAPIKeyError(w, http.StatusUnauthorized, "SERVICE002", "Invalid API key")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeAPIKeyError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
		"success": false,
	})
}
