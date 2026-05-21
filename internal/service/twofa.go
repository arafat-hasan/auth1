package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/model/domain"
)

func (s *authServiceImpl) Setup2FA(ctx context.Context, userID uuid.UUID) (*domain.TOTPSetupData, error) {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Setting up 2FA")

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	secret, err := s.totpManager.GenerateSecret(user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	if err = s.redisRepo.SetTOTPSecret(ctx, userID, secret, s.config.TOTPSecretTTL); err != nil {
		return nil, fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	return &domain.TOTPSetupData{
		Secret:    secret,
		QRCodeURL: s.totpManager.GenerateQRCodeURL(user.Email, secret),
	}, nil
}

func (s *authServiceImpl) Verify2FA(ctx context.Context, req *Verify2FARequest) (*domain.TokenPair, error) {
	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserID,
	}).Info("Verifying 2FA")

	user, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	var secret string
	if user.Is2FAEnabled && user.TOTPSecret != nil {
		secret = *user.TOTPSecret
	} else {
		secret, err = s.redisRepo.GetTOTPSecret(ctx, req.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to get TOTP secret: %w", err)
		}
		if secret == "" {
			return nil, fmt.Errorf("2FA setup not found or expired")
		}
	}

	if !s.totpManager.ValidateCode(req.TwoFACode, secret) {
		return nil, fmt.Errorf("invalid 2FA code")
	}

	// First-time verification: persist the secret and enable 2FA.
	if !user.Is2FAEnabled {
		if err = s.userRepo.Enable2FA(ctx, req.UserID, secret); err != nil {
			return nil, fmt.Errorf("failed to enable 2FA: %w", err)
		}
		s.redisRepo.DeleteTOTPSecret(ctx, req.UserID)
	}

	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.userRepo.UpdateLastLogin(ctx, req.UserID, nil, nil)

	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserID,
	}).Info("2FA verified successfully")

	return tokens, nil
}

func (s *authServiceImpl) Disable2FA(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Disabling 2FA")

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if !user.Is2FAEnabled {
		return fmt.Errorf("2FA is not enabled for this user")
	}

	if err = s.userRepo.Disable2FA(ctx, userID); err != nil {
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	// Revoke all sessions as a security measure after disabling 2FA.
	if err = s.redisRepo.DeleteAllRefreshTokens(ctx, userID); err != nil {
		s.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("Failed to revoke refresh tokens after disabling 2FA")
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("2FA disabled successfully")

	return nil
}
