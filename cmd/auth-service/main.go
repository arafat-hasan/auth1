package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	httpSwagger "github.com/swaggo/http-swagger"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"

	_ "auth1/docs" // Import for swagger docs
	v1 "auth1/internal/app/handler/v1"
	chiMiddleware "auth1/internal/app/middleware"
	"auth1/internal/app/model/api"
	"auth1/internal/app/repo"
	"auth1/internal/client/email"
	"auth1/internal/config"
	"auth1/internal/service"
	"auth1/internal/utils"
)

// @title auth1 API
// @version 1.0
// @description A secure authentication microservice with JWT, OTP, and 2FA support
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Setup logger
	logger := logrus.New()
	level, err := logrus.ParseLevel(cfg.App.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.JSONFormatter{})

	logger.Info("Starting auth1 service")

	// Setup database
	db, err := setupDatabase(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to setup database: %v", err)
	}
	defer db.Close()

	// Setup Redis
	redisClient, err := setupRedis(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to setup Redis: %v", err)
	}
	defer redisClient.Close()

	// Setup dependencies
	userRepo := repo.NewUserRepository(db)
	redisRepo := repo.NewRedisRepository(redisClient)

	emailClient := email.NewClient(
		cfg.Email.ServiceURL,
		time.Duration(cfg.Email.Timeout)*time.Second,
		cfg.Email.RetryCount,
		logger,
	)

	jwtManager := utils.NewJWTManager(
		cfg.JWT.PrivateKey,
		cfg.JWT.PublicKey,
		cfg.JWT.AccessTokenTTL,
		cfg.JWT.RefreshTokenTTL,
	)

	totpManager := utils.NewTOTPManager(cfg.App.Name)

	// Create service
	serviceConfig := &service.Config{
		OTPLength:       cfg.App.OTPLength,
		OTPTTL:          time.Duration(cfg.App.OTPTTL) * time.Second,
		PendingUserTTL:  10 * time.Minute,
		RefreshTokenTTL: time.Duration(cfg.JWT.RefreshTokenTTL) * time.Second,
		TOTPSecretTTL:   5 * time.Minute,
		PublicKeyPEM:    cfg.JWT.PublicKeyPEM,
	}

	authService := service.NewAuthService(
		userRepo,
		redisRepo,
		emailClient,
		jwtManager,
		totpManager,
		logger,
		serviceConfig,
	)

	// Setup router
	router := setupRouter(authService, jwtManager, logger)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.WithFields(logrus.Fields{
			"host": cfg.Server.Host,
			"port": cfg.Server.Port,
		}).Info("Starting HTTP server")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Errorf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited")
}

func setupDatabase(cfg *config.Config, logger *logrus.Logger) (*bun.DB, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
		cfg.Database.SSLMode,
	)

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db := bun.NewDB(sqldb, pgdialect.New())

	// Add query hook for debugging in development
	if cfg.App.Environment == "development" {
		db.AddQueryHook(bundebug.NewQueryHook(
			bundebug.WithVerbose(true),
			bundebug.FromEnv("BUNDEBUG"),
		))
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	logger.Info("Database connected successfully")
	return db, nil
}

func setupRedis(cfg *config.Config, logger *logrus.Logger) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info("Redis connected successfully")
	return client, nil
}

func setupRouter(authService service.AuthService, jwtManager *utils.JWTManager, logger *logrus.Logger) chi.Router {
	r := chi.NewRouter()

	// Setup middleware
	loggingMiddleware := chiMiddleware.NewChiLoggingMiddleware(logger)

	r.Use(middleware.RequestID)
	r.Use(loggingMiddleware.Logger())
	r.Use(loggingMiddleware.Recovery())
	r.Use(chiMiddleware.CORS())
	r.Use(render.SetContentType(render.ContentTypeJSON))

	// Health check endpoint
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, &api.HealthResponse{
			Status:  "healthy",
			Service: "auth1",
			Version: "1.0.0",
		})
	})

	// Swagger documentation
	r.Get("/swagger/*", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	// API versioning
	r.Route("/api", func(r chi.Router) {
		r.Route("/v1", func(r chi.Router) {
			// Setup v1 handlers
			authHandler := v1.NewAuthHandler(authService, jwtManager, logger)
			authHandler.RegisterRoutes(r)
		})
	})

	return r
}
