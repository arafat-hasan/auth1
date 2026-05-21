package main

import (
	"context"
	"database/sql"
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

	v1 "github.com/arafat-hasan/duitara/services/auth-service/internal/app/handler/v1"
	appMiddleware "github.com/arafat-hasan/duitara/services/auth-service/internal/app/middleware"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/repo"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/config"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/publisher"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/service"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/utils"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/worker"
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

	// ── Email publisher (outbox writer) ───────────────────────────────────────
	var emailPub publisher.EmailPublisher = publisher.NewOutboxWriter(db)

	// ── Utilities ─────────────────────────────────────────────────────────────
	jwtManager := utils.NewJWTManager(
		cfg.JWT.PrivateKey, cfg.JWT.PublicKey,
		cfg.JWT.AccessTokenTTL, cfg.JWT.RefreshTokenTTL,
	)
	totpManager := utils.NewTOTPManager(cfg.App.Name)

	// ── Service ───────────────────────────────────────────────────────────────
	svcConfig := &service.Config{
		OTPLength:                cfg.App.OTPLength,
		OTPTTL:                   time.Duration(cfg.App.OTPTTL) * time.Second,
		PendingUserTTL:           10 * time.Minute,
		RefreshTokenTTL:          time.Duration(cfg.JWT.RefreshTokenTTL) * time.Second,
		TOTPSecretTTL:            10 * time.Minute,
		PasswordResetTTL:         time.Duration(cfg.Security.PasswordResetTTL) * time.Minute,
		PublicKeyPEM:             cfg.JWT.PublicKeyPEM,
		MaxLoginAttempts:         cfg.Security.MaxLoginAttempts,
		LockoutDuration:          time.Duration(cfg.Security.LockoutDurationMinutes) * time.Minute,
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
	r.Use(appMiddleware.RequestID())
	r.Use(loggingMw.Logger())
	r.Use(loggingMw.Recovery())
	r.Use(appMiddleware.CORS())
	r.Use(chiMiddleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","service":"auth-service","version":"2.0.0"}`)
	})

	authHandler := v1.NewAuthHandler(authService, jwtManager, logger)
	r.Route("/api/v1", func(r chi.Router) {
		authHandler.RegisterRoutes(r)
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
