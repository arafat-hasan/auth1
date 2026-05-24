package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/auth1/internal/app/model/domain"
	"github.com/arafat-hasan/auth1/internal/utils"
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

	// Encrypt the secret before storing in Redis.
	encSecret, err := utils.EncryptAESGCM(secret, s.config.TOTPEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	if err = s.redisRepo.SetTOTPSecret(ctx, userID, encSecret, s.config.TOTPSecretTTL); err != nil {
		return nil, fmt.Errorf("failed to store TOTP secret: %w", err)
	}

	// Return plaintext secret so the user can scan the QR code in their authenticator app.
	return &domain.TOTPSetupData{
		Secret:    secret,
		QRCodeURL: s.totpManager.GenerateQRCodeURL(user.Email, secret),
	}, nil
}

// Confirm2FASetup validates the TOTP code against the temporary secret stored in Redis
// during Setup2FA, then persists the encrypted secret to the DB and enables 2FA.
// It does NOT issue JWT tokens — call this from an authenticated endpoint.
func (s *authServiceImpl) Confirm2FASetup(ctx context.Context, req *Confirm2FASetupRequest) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserID,
	}).Info("Confirming 2FA setup")

	encSecret, err := s.redisRepo.GetTOTPSecret(ctx, req.UserID)
	if err != nil {
		return fmt.Errorf("failed to retrieve TOTP secret: %w", err)
	}
	if encSecret == "" {
		return fmt.Errorf("2FA setup not found or expired")
	}

	secret, err := utils.DecryptAESGCM(encSecret, s.config.TOTPEncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	if !s.totpManager.ValidateCode(req.TwoFACode, secret) {
		return fmt.Errorf("invalid 2FA code")
	}

	// Encrypt for DB storage.
	encForDB, err := utils.EncryptAESGCM(secret, s.config.TOTPEncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt TOTP secret for storage: %w", err)
	}

	if err = s.userRepo.Enable2FA(ctx, req.UserID, encForDB); err != nil {
		return fmt.Errorf("failed to enable 2FA: %w", err)
	}

	// Clean up temporary secret from Redis.
	s.redisRepo.DeleteTOTPSecret(ctx, req.UserID)

	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserID,
	}).Info("2FA setup confirmed and enabled")

	return nil
}

// Verify2FALogin validates a challenge token (issued by Login when 2FA is required) plus a
// TOTP code, then issues JWT tokens on success. The challenge token is single-use.
func (s *authServiceImpl) Verify2FALogin(ctx context.Context, req *Verify2FALoginRequest) (*domain.TokenPair, error) {
	s.logger.Info("Verifying 2FA login challenge")

	userID, err := s.redisRepo.GetTwoFAChallenge(ctx, req.ChallengeToken)
	if err != nil {
		return nil, fmt.Errorf("failed to look up 2FA challenge: %w", err)
	}
	if userID == uuid.Nil {
		return nil, fmt.Errorf("invalid or expired 2FA challenge")
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	if !user.Is2FAEnabled || user.TOTPSecret == nil {
		return nil, fmt.Errorf("2FA not properly configured for this user")
	}

	secret, err := utils.DecryptAESGCM(*user.TOTPSecret, s.config.TOTPEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	if !s.totpManager.ValidateCode(req.TwoFACode, secret) {
		// Do not delete the challenge on failure; let it expire naturally.
		return nil, fmt.Errorf("invalid 2FA code")
	}

	// Challenge is single-use: delete immediately on success.
	s.redisRepo.DeleteTwoFAChallenge(ctx, req.ChallengeToken)

	tokens, err := s.generateTokens(ctx, user.ID, user.Email, user.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.userRepo.UpdateLastLogin(ctx, userID, nil, nil)

	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("2FA login verified successfully")

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
