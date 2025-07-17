package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type LoggingMiddleware struct {
	logger *logrus.Logger
}

func NewLoggingMiddleware(logger *logrus.Logger) *LoggingMiddleware {
	return &LoggingMiddleware{
		logger: logger,
	}
}

func (l *LoggingMiddleware) LogRequests() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Process request
		c.Next()

		// Log after processing
		latency := time.Since(startTime)

		// Get user ID if available
		userID, hasUserID := GetUserID(c)

		fields := logrus.Fields{
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"status":     c.Writer.Status(),
			"latency":    latency,
			"ip":         c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
		}

		// Add user ID if available
		if hasUserID {
			fields["user_id"] = userID
		}

		// Add query parameters if present
		if c.Request.URL.RawQuery != "" {
			fields["query"] = c.Request.URL.RawQuery
		}

		// Log with appropriate level based on status code
		switch {
		case c.Writer.Status() >= 500:
			l.logger.WithFields(fields).Error("HTTP request")
		case c.Writer.Status() >= 400:
			l.logger.WithFields(fields).Warn("HTTP request")
		default:
			l.logger.WithFields(fields).Info("HTTP request")
		}
	}
}

func (l *LoggingMiddleware) LogErrors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Log any errors that occurred during processing
		if len(c.Errors) > 0 {
			for _, err := range c.Errors {
				l.logger.WithFields(logrus.Fields{
					"method": c.Request.Method,
					"path":   c.Request.URL.Path,
					"error":  err.Error(),
				}).Error("Request error")
			}
		}
	}
}
