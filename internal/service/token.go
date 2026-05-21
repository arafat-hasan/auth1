package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/model/domain"
)

func (s *authServiceImpl) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*domain.TokenPair, error) {
	s.logger.Info("Refreshing token")

	claims, err := s.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in token: %w", err)
	}

	exists, err := s.redisRepo.GetRefreshToken(ctx, userID, claims.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check refresh token: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("refresh token not found or expired")
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Rotate: delete the old token before issuing a new one.
	s.redisRepo.DeleteRefreshToken(ctx, userID, claims.ID)

	tokens, err := s.generateTokens(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": user.ID,
	}).Info("Token refreshed successfully")

	return tokens, nil
}

func (s *authServiceImpl) Logout(ctx context.Context, req *LogoutRequest) error {
	s.logger.Info("Logging out user")

	claims, err := s.jwtManager.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return fmt.Errorf("invalid refresh token: %w", err)
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return fmt.Errorf("invalid user ID in token: %w", err)
	}

	if err = s.redisRepo.DeleteRefreshToken(ctx, userID, claims.ID); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("User logged out successfully")

	return nil
}

func (s *authServiceImpl) LogoutAllDevices(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Logging out all devices")

	if err := s.redisRepo.DeleteAllRefreshTokens(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke all sessions: %w", err)
	}

	return nil
}
