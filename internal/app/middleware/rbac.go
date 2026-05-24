package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/sirupsen/logrus"
)

// RequireRole returns middleware that checks the authenticated user has at least
// one of the given roles. Must be used after Authenticate middleware.
func RequireRole(logger *logrus.Logger, roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRoles, _ := r.Context().Value("roles").([]string)
			for _, role := range userRoles {
				if allowed[role] {
					next.ServeHTTP(w, r)
					return
				}
			}
			if logger != nil {
				logger.WithFields(logrus.Fields{
					"required": roles,
					"actual":   userRoles,
					"path":     r.URL.Path,
					"method":   r.Method,
					"ip":       GetClientIP(r),
				}).Warn("RBAC: access denied")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"code":    "RBAC403",
					"message": "Insufficient permissions",
				},
			})
		})
	}
}

// RequireAdmin is shorthand for RequireRole("admin").
func RequireAdmin(logger *logrus.Logger) func(http.Handler) http.Handler {
	return RequireRole(logger, "admin")
}
