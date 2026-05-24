package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/auth1/internal/app/model/db"
	"github.com/arafat-hasan/auth1/internal/app/model/domain"
	"github.com/arafat-hasan/auth1/internal/publisher"
	"github.com/arafat-hasan/auth1/internal/utils"
)

func (s *authServiceImpl) RequestPasswordReset(ctx context.Context, req *PasswordResetRequest) error {
	s.logger.WithFields(logrus.Fields{
		"email": req.Email,
		"phone": req.Phone,
	}).Info("Requesting password reset")

	var user *domain.User
	var err error

	switch {
	case req.Email != "":
		user, err = s.userRepo.GetByEmail(ctx, req.Email)
	case req.Phone != "":
		user, err = s.userRepo.GetByPhone(ctx, req.Phone)
	default:
		return fmt.Errorf("email or phone is required")
	}

	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		// Silently succeed to avoid revealing whether the account exists.
		return nil
	}

	rawToken, err := utils.GenerateRandomString(32)
	if err != nil {
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	resetToken := &db.PasswordResetToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(s.config.PasswordResetTTL),
		IPAddress: req.IPAddress,
	}

	if err = s.userRepo.CreatePasswordResetToken(ctx, resetToken); err != nil {
		return fmt.Errorf("failed to create password reset token: %w", err)
	}

	if user.Email != "" {
		event := &publisher.EmailEvent{
			RoutingKey: publisher.RoutingKeyEmailPasswordReset,
			EventType:  "password_reset",
			To:         user.Email,
			Subject:    "Password Reset Request",
			Template:   "password_reset",
			Variables: map[string]string{
				"name":  user.Name,
				"token": rawToken,
			},
		}
		if err = s.emailPublisher.Enqueue(ctx, event); err != nil {
			s.logger.WithFields(logrus.Fields{
				"user_id": user.ID,
				"error":   err.Error(),
			}).Error("Failed to enqueue password reset email")
		}
	}

	return nil
}

func (s *authServiceImpl) VerifyPasswordResetToken(ctx context.Context, token string) (*domain.User, error) {
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	resetToken, err := s.userRepo.GetPasswordResetToken(ctx, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get reset token: %w", err)
	}
	if resetToken == nil {
		return nil, fmt.Errorf("invalid or expired password reset token")
	}

	user, err := s.userRepo.GetByID(ctx, resetToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

func (s *authServiceImpl) ResetPassword(ctx context.Context, req *ResetPasswordRequest) error {
	s.logger.Info("Resetting password")

	hash := sha256.Sum256([]byte(req.Token))
	tokenHash := hex.EncodeToString(hash[:])

	resetToken, err := s.userRepo.GetPasswordResetToken(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("failed to get reset token: %w", err)
	}
	if resetToken == nil {
		return fmt.Errorf("invalid or expired password reset token")
	}

	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err = s.userRepo.UpdatePassword(ctx, resetToken.UserID, hashedPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	if err = s.userRepo.MarkPasswordResetTokenAsUsed(ctx, resetToken.ID); err != nil {
		s.logger.WithFields(logrus.Fields{
			"token_id": resetToken.ID,
			"error":    err.Error(),
		}).Error("Failed to mark reset token as used")
	}

	// 🔒 Revoke all active sessions after a password reset.
	// Blacklist all user's JWTs (force re-login)
	maxTokenLifetime := s.jwtManager.GetAccessTokenTTL()
	if err := s.redisRepo.BlacklistAllUserJWTs(ctx, resetToken.UserID, maxTokenLifetime); err != nil {
		s.logger.WithError(err).Error("Failed to blacklist user tokens after password reset")
		// Continue - security measure, not critical for reset success
	}

	// Delete all refresh tokens
	s.redisRepo.DeleteAllRefreshTokens(ctx, resetToken.UserID)

	s.logger.WithFields(logrus.Fields{
		"user_id": resetToken.UserID,
	}).Info("Password reset successfully, all tokens revoked")

	return nil
}

func (s *authServiceImpl) ChangePassword(ctx context.Context, req *ChangePasswordRequest) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserID,
	}).Info("Changing password")

	user, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if user.PasswordHash == nil || !utils.CheckPasswordHash(req.OldPassword, *user.PasswordHash) {
		return fmt.Errorf("invalid current password")
	}

	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err = s.userRepo.UpdatePassword(ctx, req.UserID, hashedPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// 🔒 Revoke all active sessions after password change (force re-login on all devices)
	// Blacklist all user's JWTs
	maxTokenLifetime := s.jwtManager.GetAccessTokenTTL()
	if err := s.redisRepo.BlacklistAllUserJWTs(ctx, req.UserID, maxTokenLifetime); err != nil {
		s.logger.WithError(err).Error("Failed to blacklist user tokens after password change")
		// Continue - security measure, not critical for password change success
	}

	// Delete all refresh tokens
	if err := s.redisRepo.DeleteAllRefreshTokens(ctx, req.UserID); err != nil {
		s.logger.WithError(err).Error("Failed to delete refresh tokens after password change")
		// Continue
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserID,
	}).Info("Password changed successfully, all tokens revoked")

	return nil
}
