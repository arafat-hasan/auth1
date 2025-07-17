package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// ChiLoggingMiddleware provides structured logging for Chi router
type ChiLoggingMiddleware struct {
	logger *logrus.Logger
}

// NewChiLoggingMiddleware creates a new logging middleware for Chi
func NewChiLoggingMiddleware(logger *logrus.Logger) *ChiLoggingMiddleware {
	return &ChiLoggingMiddleware{
		logger: logger,
	}
}

// Logger returns a Chi-compatible logging middleware
func (l *ChiLoggingMiddleware) Logger() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			t1 := time.Now()
			defer func() {
				latency := time.Since(t1)

				// Get user ID if available
				var userID *uuid.UUID
				if uid, ok := r.Context().Value("user_id").(uuid.UUID); ok {
					userID = &uid
				}

				fields := logrus.Fields{
					"method":     r.Method,
					"path":       r.URL.Path,
					"status":     ww.Status(),
					"latency":    latency,
					"ip":         r.RemoteAddr,
					"user_agent": r.UserAgent(),
					"bytes":      ww.BytesWritten(),
				}

				// Add user ID if available
				if userID != nil {
					fields["user_id"] = *userID
				}

				// Add query parameters if present
				if r.URL.RawQuery != "" {
					fields["query"] = r.URL.RawQuery
				}

				// Log with appropriate level based on status code
				switch {
				case ww.Status() >= 500:
					l.logger.WithFields(fields).Error("HTTP request")
				case ww.Status() >= 400:
					l.logger.WithFields(fields).Warn("HTTP request")
				default:
					l.logger.WithFields(fields).Info("HTTP request")
				}
			}()

			next.ServeHTTP(ww, r)
		}
		return http.HandlerFunc(fn)
	}
}

// Recovery returns a Chi-compatible recovery middleware
func (l *ChiLoggingMiddleware) Recovery() func(next http.Handler) http.Handler {
	return middleware.Recoverer
}

// RequestID returns a Chi-compatible request ID middleware
func RequestID() func(next http.Handler) http.Handler {
	return middleware.RequestID
}

// CORS returns a basic CORS middleware
func CORS() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
			w.Header().Set("Access-Control-Expose-Headers", "Content-Length")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "43200")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
