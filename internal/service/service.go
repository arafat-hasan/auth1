package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/model/domain"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/repo"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/publisher"
	"github.com/arafat-hasan/duitara/services/auth-service/internal/utils"
)

// authServiceImpl is the concrete implementation of AuthService.
type authServiceImpl struct {
	userRepo       repo.UserRepository
	redisRepo      repo.RedisRepository
	emailPublisher publisher.EmailPublisher
	jwtManager     *utils.JWTManager
	totpManager    *utils.TOTPManager
	logger         *logrus.Logger
	config         *Config
}

// NewAuthService creates a new AuthService.
func NewAuthService(
	userRepo repo.UserRepository,
	redisRepo repo.RedisRepository,
	emailPublisher publisher.EmailPublisher,
	jwtManager *utils.JWTManager,
	totpManager *utils.TOTPManager,
	logger *logrus.Logger,
	config *Config,
) AuthService {
	return &authServiceImpl{
		userRepo:       userRepo,
		redisRepo:      redisRepo,
		emailPublisher: emailPublisher,
		jwtManager:     jwtManager,
		totpManager:    totpManager,
		logger:         logger,
		config:         config,
	}
}

// generateTokens creates a new access/refresh token pair and stores the refresh token in Redis.
func (s *authServiceImpl) generateTokens(ctx context.Context, userID uuid.UUID, userEmail string) (*domain.TokenPair, error) {
	accessToken, err := s.jwtManager.GenerateAccessToken(userID, userEmail, []string{"user"})
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, jti, err := s.jwtManager.GenerateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	if err = s.redisRepo.SetRefreshToken(ctx, userID, jti, s.config.RefreshTokenTTL); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.jwtManager.GetAccessTokenTTL().Seconds()),
	}, nil
}

// generateAndSendOTP creates an OTP, hashes and stores it in Redis, then enqueues an
// email event in the transactional outbox. The outbox relay delivers it asynchronously.
// It rejects the request if a valid OTP already exists to prevent spam.
func (s *authServiceImpl) generateAndSendOTP(ctx context.Context, emailAddr, purpose string) error {
	exists, err := s.redisRepo.OTPExists(ctx, emailAddr, purpose)
	if err != nil {
		return fmt.Errorf("failed to check OTP existence: %w", err)
	}
	if exists {
		return fmt.Errorf("OTP already sent, please wait before requesting another")
	}

	otp, err := utils.GenerateOTP(s.config.OTPLength)
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	hashedOTP := utils.HashOTP(otp)
	if err = s.redisRepo.SetOTP(ctx, emailAddr, purpose, hashedOTP, s.config.OTPTTL); err != nil {
		return fmt.Errorf("failed to store OTP: %w", err)
	}

	subject, template := otpEmailMeta(purpose)
	event := &publisher.EmailEvent{
		IdempotencyKey: fmt.Sprintf("otp:%s:%s", emailAddr, purpose),
		RoutingKey:     publisher.RoutingKeyEmailOTP,
		EventType:      purpose + "_otp",
		To:             emailAddr,
		Subject:        subject,
		Template:       template,
		Variables: map[string]string{
			"otp":    otp,
			"expiry": "5 minutes",
		},
	}

	if err = s.emailPublisher.Enqueue(ctx, event); err != nil {
		s.redisRepo.DeleteOTP(ctx, emailAddr, purpose)
		return fmt.Errorf("failed to enqueue OTP email: %w", err)
	}

	return nil
}

func otpEmailMeta(purpose string) (subject, template string) {
	switch purpose {
	case "signup":
		return "Verify Your Account", "signup_otp"
	case "login":
		return "Login Verification Code", "login_otp"
	default:
		return "Verification Code", "generic_otp"
	}
}

// verifyOTP checks whether the provided OTP matches the hashed value stored in Redis.
func (s *authServiceImpl) verifyOTP(ctx context.Context, identifier, purpose, otp string) bool {
	storedHash, err := s.redisRepo.GetOTP(ctx, identifier, purpose)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"identifier": identifier,
			"purpose":    purpose,
			"error":      err.Error(),
		}).Error("Failed to get OTP from Redis")
		return false
	}

	if storedHash == "" {
		return false
	}

	return utils.ValidateOTP(otp, storedHash)
}
