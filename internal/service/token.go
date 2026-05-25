package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/auth1/internal/app/middleware"
	"github.com/arafat-hasan/auth1/internal/app/model/domain"
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

	tokens, err := s.generateTokens(ctx, user.ID, user.Email, user.Role, derefStr(req.IPAddress), derefStr(req.UserAgent))
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

	// Get access token JTI from context (set by auth middleware)
	jti := middleware.GetJTIFromContext(ctx)
	issuedAt := middleware.GetIssuedAtFromContext(ctx)

	// Blacklist the access token (JWT)
	if jti != "" {
		// Calculate token expiration time
		expiresAt := time.Unix(issuedAt, 0).Add(s.jwtManager.GetAccessTokenTTL())

		// Blacklist the JWT
		err := s.redisRepo.BlacklistJWT(ctx, jti, expiresAt)
		if err != nil {
			s.logger.WithError(err).Error("Failed to blacklist JWT on logout")
			// Continue anyway - token will expire naturally
		} else {
			s.logger.WithField("jti", jti).Info("Access token blacklisted")
		}
	} else {
		s.logger.Warn("No JTI found in context during logout")
	}

	// Also revoke refresh token (existing logic)
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
		"jti":     jti,
	}).Info("User logged out successfully")

	return nil
}

func (s *authServiceImpl) LogoutAllDevices(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Logging out all devices")

	// Blacklist all user's JWTs (max token lifetime as TTL)
	maxTokenLifetime := s.jwtManager.GetAccessTokenTTL()
	if err := s.redisRepo.BlacklistAllUserJWTs(ctx, userID, maxTokenLifetime); err != nil {
		s.logger.WithError(err).Error("Failed to blacklist all user JWTs")
		// Continue anyway
	}

	// Delete all refresh tokens
	if err := s.redisRepo.DeleteAllRefreshTokens(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke all sessions: %w", err)
	}

	s.logger.WithField("user_id", userID).Info("All user tokens and sessions revoked")

	return nil
}
