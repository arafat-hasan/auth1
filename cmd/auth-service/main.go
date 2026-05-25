// @title           Auth Service API
// @version         1.0.0
// @description     JWT-based authentication service with OTP, 2FA, and RBAC.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:8080
// @BasePath  /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer " followed by your access token

package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"

	httpSwagger "github.com/swaggo/http-swagger"

	_ "github.com/arafat-hasan/auth1/docs"
	v1 "github.com/arafat-hasan/auth1/internal/app/handler/v1"
	appMiddleware "github.com/arafat-hasan/auth1/internal/app/middleware"
	"github.com/arafat-hasan/auth1/internal/app/repo"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/health"
	"github.com/arafat-hasan/auth1/internal/publisher"
	"github.com/arafat-hasan/auth1/internal/ratelimit"
	"github.com/arafat-hasan/auth1/internal/service"
	"github.com/arafat-hasan/auth1/internal/utils"
	"github.com/arafat-hasan/auth1/internal/worker"
)

// Build-time variables — set via: go build -ldflags "-X main.version=1.2.3 -X main.gitCommit=abc1234 -X main.buildDate=2026-05-25"
var (
	version   = "dev"
	gitCommit = "unknown"
	buildDate = "unknown"
)

func main() {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	cfg, err := config.Load()
	if err != nil {
		logger.WithError(err).Fatal("failed to load config")
	}

	level, err := logrus.ParseLevel(cfg.App.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// ── Database ──────────────────────────────────────────────────────────────
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.Database.User, cfg.Database.Password,
		cfg.Database.Host, cfg.Database.Port,
		cfg.Database.Name, cfg.Database.SSLMode,
	)
	if cfg.Database.Schema != "" {
		dsn += "&search_path=" + cfg.Database.Schema
	}
	sqlDB := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db := bun.NewDB(sqlDB, pgdialect.New())
	if cfg.App.LogLevel == "debug" {
		db.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))
	}

	if err = db.PingContext(context.Background()); err != nil {
		logger.WithError(err).Fatal("failed to connect to database")
	}
	logger.Info("Database connected successfully")
	defer db.Close()

	// ── Redis ─────────────────────────────────────────────────────────────────
	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err = redisClient.Ping(context.Background()).Err(); err != nil {
		logger.WithError(err).Fatal("failed to connect to Redis")
	}
	logger.Info("Redis connected successfully")
	defer redisClient.Close()

	// ── Repositories ──────────────────────────────────────────────────────────
	userRepo := repo.NewUserRepository(db)
	redisRepo := repo.NewRedisRepository(redisClient)
	outboxRepo := repo.NewOutboxRepository(db)

	// ── Rate Limiter ──────────────────────────────────────────────────────────
	rateLimiter := ratelimit.NewRateLimiter(redisClient)
	logger.Info("Rate limiter initialized")

	// ── Email publisher (outbox writer) ───────────────────────────────────────
	var emailPub publisher.EmailPublisher = publisher.NewOutboxWriter(db)

	// ── Utilities ─────────────────────────────────────────────────────────────
	jwtManager := utils.NewJWTManager(
		cfg.JWT.PrivateKey, cfg.JWT.PublicKey,
		cfg.JWT.AccessTokenTTL, cfg.JWT.RefreshTokenTTL,
	)
	totpManager := utils.NewTOTPManager(cfg.App.Name)

	// ── Service ───────────────────────────────────────────────────────────────
	totpEncKey, err := base64.StdEncoding.DecodeString(cfg.App.TOTPEncryptionKey)
	if err != nil {
		logger.WithError(err).Fatal("failed to decode TOTP encryption key")
	}

	svcConfig := &service.Config{
		OTPLength:                cfg.App.OTPLength,
		OTPTTL:                   time.Duration(cfg.App.OTPTTL) * time.Second,
		PendingUserTTL:           10 * time.Minute,
		RefreshTokenTTL:          time.Duration(cfg.JWT.RefreshTokenTTL) * time.Second,
		TOTPSecretTTL:            10 * time.Minute,
		TOTPChallengeTTL:         time.Duration(cfg.App.TOTPChallengeTTLSec) * time.Second,
		PasswordResetTTL:         time.Duration(cfg.Security.PasswordResetTTL) * time.Minute,
		MaxLoginAttempts:         cfg.Security.MaxLoginAttempts,
		LockoutDuration:          time.Duration(cfg.Security.LockoutDurationMinutes) * time.Minute,
		TOTPEncryptionKey:        totpEncKey,
		EnableEmailAuth:          cfg.App.EnableEmailAuth,
		EnablePhoneAuth:          cfg.App.EnablePhoneAuth,
		EnablePasswordAuth:       cfg.App.EnablePasswordAuth,
		EnableOTPAuth:            cfg.App.EnableOTPAuth,
		Enable2FA:                cfg.App.Enable2FA,
		EnableAuditLog:           cfg.App.EnableAuditLog,
		RequireEmailVerification: cfg.App.RequireEmailVerification,
		RequirePhoneVerification: cfg.App.RequirePhoneVerification,
	}

	authService := service.NewAuthService(
		userRepo, redisRepo, emailPub,
		jwtManager, totpManager,
		logger, svcConfig,
	)

	// ── HTTP router ───────────────────────────────────────────────────────────
	r := chi.NewRouter()

	loggingMw := appMiddleware.NewChiLoggingMiddleware(logger)
	// ── Rate limiting configuration ───────────────────────────────────────────
	rlCfg := cfg.RateLimit

	r.Use(appMiddleware.RequestID())
	r.Use(loggingMw.Logger())
	r.Use(loggingMw.Recovery())
	r.Use(appMiddleware.CORS())
	r.Use(chiMiddleware.Timeout(30 * time.Second))

	// Global rate limit must be registered before any routes on this mux.
	if rlCfg.Enabled {
		r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
			Limit:   rlCfg.GlobalLimit,
			Window:  time.Duration(rlCfg.GlobalWindow) * time.Second,
			KeyFunc: appMiddleware.IPBasedKey("global"),
			Enabled: true,
			Logger:  logger,
		}))
		logger.WithFields(logrus.Fields{
			"limit":  rlCfg.GlobalLimit,
			"window": fmt.Sprintf("%ds", rlCfg.GlobalWindow),
		}).Info("Global rate limiting enabled")
	}

	healthChecker := health.NewHealthChecker(db, redisClient, cfg.AMQP.URL, outboxRepo, logger, health.BuildInfo{
		Version:   version,
		GitCommit: gitCommit,
		BuildDate: buildDate,
	})
	r.Get("/livez", healthChecker.Livez)
	r.Get("/readyz", healthChecker.Readyz)
	r.Get("/health", healthChecker.Health)

	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	authHandler := v1.NewAuthHandler(authService, jwtManager, logger)
	userHandler := v1.NewUserHandler(authService, logger)

	// JWKS at the RFC 8414 well-known location — downstream services poll this at startup.
	r.Get("/.well-known/jwks.json", authHandler.GetJWKS)

	r.Route("/api/v1/auth", func(r chi.Router) {
		// ── Public endpoints with specific rate limits ─────────────────────

		// Login endpoint - dual rate limiting (IP + Email)
		r.Group(func(r chi.Router) {
			if rlCfg.Enabled {
				// Rate limit by IP
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.LoginIPLimit,
					Window:  time.Duration(rlCfg.LoginIPWindow) * time.Second,
					KeyFunc: appMiddleware.IPBasedKey("login"),
					Enabled: true,
					Logger:  logger,
				}))

				// Rate limit by email
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.LoginEmailLimit,
					Window:  time.Duration(rlCfg.LoginEmailWindow) * time.Second,
					KeyFunc: appMiddleware.EmailBasedKey("login"),
					Enabled: true,
					Logger:  logger,
				}))
			}

			r.Post("/login", authHandler.Login)
		})

		// Signup endpoint - IP-based rate limiting
		r.Group(func(r chi.Router) {
			if rlCfg.Enabled {
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.SignupIPLimit,
					Window:  time.Duration(rlCfg.SignupIPWindow) * time.Second,
					KeyFunc: appMiddleware.IPBasedKey("signup"),
					Enabled: true,
					Logger:  logger,
				}))
			}

			r.Post("/signup", authHandler.Signup)
		})

		// Verify signup - Email-based rate limiting
		r.Group(func(r chi.Router) {
			if rlCfg.Enabled {
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.OTPVerifyEmailLimit,
					Window:  time.Duration(rlCfg.OTPVerifyEmailWindow) * time.Second,
					KeyFunc: appMiddleware.EmailBasedKey("verify-signup"),
					Enabled: true,
					Logger:  logger,
				}))
			}

			r.Post("/verify-signup", authHandler.VerifySignup)
		})

		// Request OTP - Email-based rate limiting
		r.Group(func(r chi.Router) {
			if rlCfg.Enabled {
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.OTPEmailLimit,
					Window:  time.Duration(rlCfg.OTPEmailWindow) * time.Second,
					KeyFunc: appMiddleware.EmailBasedKey("request-otp"),
					Enabled: true,
					Logger:  logger,
				}))
			}

			r.Post("/request-otp", authHandler.RequestOTP)
		})

		// Verify login OTP - Email-based rate limiting
		r.Group(func(r chi.Router) {
			if rlCfg.Enabled {
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.OTPVerifyEmailLimit,
					Window:  time.Duration(rlCfg.OTPVerifyEmailWindow) * time.Second,
					KeyFunc: appMiddleware.EmailBasedKey("verify-login"),
					Enabled: true,
					Logger:  logger,
				}))
			}

			r.Post("/verify-login", authHandler.VerifyLogin)
		})

		// Refresh token - Token-based rate limiting
		r.Group(func(r chi.Router) {
			if rlCfg.Enabled {
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.RefreshLimit,
					Window:  time.Duration(rlCfg.RefreshWindow) * time.Second,
					KeyFunc: appMiddleware.TokenBasedKey("refresh"),
					Enabled: true,
					Logger:  logger,
				}))
			}

			r.Post("/refresh", authHandler.RefreshToken)
		})

		// Logout - no specific rate limit (covered by global)
		r.Post("/logout", authHandler.Logout)

		// Public key - no rate limit needed
		r.Get("/jwks", authHandler.GetJWKS)

		// Forgot password - IP-based rate limiting
		r.Group(func(r chi.Router) {
			if rlCfg.Enabled {
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.SignupIPLimit,
					Window:  time.Duration(rlCfg.SignupIPWindow) * time.Second,
					KeyFunc: appMiddleware.IPBasedKey("forgot-password"),
					Enabled: true,
					Logger:  logger,
				}))
			}
			r.Post("/forgot-password", authHandler.ForgotPassword)
		})

		// Reset password - IP-based rate limiting
		r.Group(func(r chi.Router) {
			if rlCfg.Enabled {
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.SignupIPLimit,
					Window:  time.Duration(rlCfg.SignupIPWindow) * time.Second,
					KeyFunc: appMiddleware.IPBasedKey("reset-password"),
					Enabled: true,
					Logger:  logger,
				}))
			}
			r.Post("/reset-password", authHandler.ResetPassword)
		})

		// 2FA verify during login - Email-based rate limiting
		r.Group(func(r chi.Router) {
			if rlCfg.Enabled {
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.TwoFAVerifyLimit,
					Window:  time.Duration(rlCfg.TwoFAVerifyWindow) * time.Second,
					KeyFunc: appMiddleware.EmailBasedKey("2fa-verify"),
					Enabled: true,
					Logger:  logger,
				}))
			}

			r.Post("/2fa/verify", authHandler.Verify2FA)
		})

		// ── Authenticated endpoints (require JWT) ──────────────────────────
		r.Group(func(r chi.Router) {
			// Apply authentication middleware first (with JWT blacklist checking)
			r.Use(appMiddleware.Authenticate(jwtManager, redisRepo, logger))

			// Then apply user-based rate limiting
			if rlCfg.Enabled {
				r.Use(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
					Limit:   rlCfg.AuthenticatedLimit,
					Window:  time.Duration(rlCfg.AuthenticatedWindow) * time.Second,
					KeyFunc: appMiddleware.UserBasedKey("authenticated"),
					Enabled: true,
					Logger:  logger,
				}))
			}

			// User info and self-edit endpoints
			r.Get("/me", authHandler.GetMe)
			r.Put("/me", authHandler.UpdateMe)

			// Change password (authenticated)
			r.Post("/change-password", authHandler.ChangePassword)

			// 2FA setup endpoint (stricter limit)
			r.With(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
				Limit:   rlCfg.TwoFASetupLimit,
				Window:  time.Duration(rlCfg.TwoFASetupWindow) * time.Second,
				KeyFunc: appMiddleware.UserBasedKey("2fa-setup"),
				Enabled: rlCfg.Enabled,
				Logger:  logger,
			})).Post("/2fa/setup", authHandler.Setup2FA)

			// 2FA confirm setup endpoint (same rate limit as setup)
			r.With(appMiddleware.RateLimit(rateLimiter, appMiddleware.RateLimitConfig{
				Limit:   rlCfg.TwoFAVerifyLimit,
				Window:  time.Duration(rlCfg.TwoFAVerifyWindow) * time.Second,
				KeyFunc: appMiddleware.UserBasedKey("2fa-confirm"),
				Enabled: rlCfg.Enabled,
				Logger:  logger,
			})).Post("/2fa/confirm", authHandler.Confirm2FASetup)

			// 2FA disable endpoint
			r.Post("/2fa/disable", authHandler.Disable2FA)
		})
	})

	// ── Service-to-service introspect endpoint ────────────────────────────────
	// Protected by API key (Authorization: ApiKey <key>), not by user JWT.
	r.With(appMiddleware.RequireServiceAPIKey(cfg.Services.AllowedAPIKeys, logger)).
		Post("/api/v1/auth/introspect", authHandler.IntrospectToken)

	// ── User management routes (admin + self-service sessions) ───────────────
	r.Route("/api/v1/users", func(r chi.Router) {
		r.Use(appMiddleware.Authenticate(jwtManager, redisRepo, logger))

		// Admin-only endpoints
		r.Group(func(r chi.Router) {
			r.Use(appMiddleware.RequireAdmin(logger))

			r.Get("/", userHandler.ListUsers)
			r.Get("/{id}", userHandler.GetUser)
			r.Put("/{id}", userHandler.UpdateUser)
			r.Delete("/{id}", userHandler.DeleteUser)
			r.Post("/{id}/deactivate", userHandler.DeactivateUser)
			r.Post("/{id}/reactivate", userHandler.ReactivateUser)
			r.Post("/{id}/unlock", userHandler.UnlockUser)
		})

		// User-or-admin session endpoints (self-service check inside handler)
		r.Get("/{id}/sessions", userHandler.ListUserSessions)
		r.Delete("/{id}/sessions/{session_id}", userHandler.RevokeUserSession)
	})

	// ── Outbox relay ──────────────────────────────────────────────────────────
	relayCfg := worker.OutboxRelayConfig{
		PollInterval: time.Duration(cfg.AMQP.OutboxPollSecs) * time.Second,
		MaxAttempts:  cfg.AMQP.MaxAttempts,
		BatchSize:    cfg.AMQP.BatchSize,
	}
	relay := worker.NewOutboxRelay(outboxRepo, cfg.AMQP.URL, relayCfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go relay.Run(ctx)
	logger.Info("Outbox relay started")

	// ── HTTP server with graceful shutdown ────────────────────────────────────
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.WithFields(logrus.Fields{"host": cfg.Server.Host, "port": cfg.Server.Port}).
			Info("Starting HTTP server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("HTTP server error")
		}
	}()

	<-quit
	logger.Info("Shutting down server...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	}

	logger.Info("Server exited")
}
