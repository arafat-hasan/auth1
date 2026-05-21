package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/model/domain"
)

func (s *authServiceImpl) GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

func (s *authServiceImpl) GetPublicKey() string {
	return s.config.PublicKeyPEM
}

func (s *authServiceImpl) UpdateUser(ctx context.Context, userID uuid.UUID, req *UpdateUserRequest) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Updating user")

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.Phone != nil {
		user.Phone = req.Phone
	}
	user.UpdatedAt = time.Now()

	if err = s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (s *authServiceImpl) DeactivateUser(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Deactivating user")

	if err := s.userRepo.SetActiveStatus(ctx, userID, false); err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	// Revoke all active sessions immediately.
	s.redisRepo.DeleteAllRefreshTokens(ctx, userID)

	return nil
}

func (s *authServiceImpl) ReactivateUser(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Reactivating user")

	if err := s.userRepo.SetActiveStatus(ctx, userID, true); err != nil {
		return fmt.Errorf("failed to reactivate user: %w", err)
	}

	return nil
}

func (s *authServiceImpl) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Deleting user (soft delete)")

	if err := s.userRepo.SoftDelete(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Revoke all active sessions immediately.
	s.redisRepo.DeleteAllRefreshTokens(ctx, userID)

	return nil
}

func (s *authServiceImpl) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Unlocking account")

	if err := s.userRepo.UnlockAccount(ctx, userID); err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}

	return nil
}

func (s *authServiceImpl) UpdateUserRole(ctx context.Context, userID uuid.UUID, role string) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"role":    role,
	}).Info("Updating user role")

	if err := s.userRepo.UpdateRole(ctx, userID, role); err != nil {
		return fmt.Errorf("failed to update user role: %w", err)
	}

	return nil
}

func (s *authServiceImpl) UpdateUserMetadata(ctx context.Context, userID uuid.UUID, metadata map[string]interface{}) error {
	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Updating user metadata")

	if err := s.userRepo.UpdateMetadata(ctx, userID, metadata); err != nil {
		return fmt.Errorf("failed to update user metadata: %w", err)
	}

	return nil
}
