package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/auth1/internal/app/model/domain"
	"github.com/arafat-hasan/auth1/internal/app/repo"
)

func (s *authServiceImpl) GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, userID)
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
		if user.Phone == nil || *user.Phone != *req.Phone {
			user.PhoneVerifiedAt = nil
		}
		user.Phone = req.Phone
	}
	user.UpdatedAt = time.Now()

	if err = s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (s *authServiceImpl) DeactivateUser(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{"user_id": userID}).Info("Deactivating user")

	if err := s.userRepo.SetActiveStatus(ctx, userID, false); err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}
	s.redisRepo.DeleteAllRefreshTokens(ctx, userID)
	s.auditLog(ctx, nil, "user.deactivated", map[string]interface{}{"target_user_id": userID}, nil)
	return nil
}

func (s *authServiceImpl) ReactivateUser(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{"user_id": userID}).Info("Reactivating user")

	if err := s.userRepo.SetActiveStatus(ctx, userID, true); err != nil {
		return fmt.Errorf("failed to reactivate user: %w", err)
	}
	s.auditLog(ctx, nil, domain.EventUserReactivated, map[string]interface{}{"target_user_id": userID}, nil)
	return nil
}

func (s *authServiceImpl) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{"user_id": userID}).Info("Deleting user (soft delete)")

	if err := s.userRepo.SoftDelete(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	s.redisRepo.DeleteAllRefreshTokens(ctx, userID)
	s.auditLog(ctx, nil, domain.EventUserDeleted, map[string]interface{}{"target_user_id": userID}, nil)
	return nil
}

func (s *authServiceImpl) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	s.logger.WithFields(logrus.Fields{"user_id": userID}).Info("Unlocking account")

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if err := s.redisRepo.ResetLoginAttempts(ctx, user.Email, "email"); err != nil {
		return fmt.Errorf("failed to clear login attempts: %w", err)
	}

	s.auditLog(ctx, nil, domain.EventUserUnlocked, map[string]interface{}{"target_user_id": userID}, nil)
	return nil
}

func (s *authServiceImpl) UpdateUserRole(ctx context.Context, userID uuid.UUID, role string) error {
	s.logger.WithFields(logrus.Fields{"user_id": userID, "role": role}).Info("Updating user role")

	if err := s.userRepo.UpdateRole(ctx, userID, role); err != nil {
		return fmt.Errorf("failed to update user role: %w", err)
	}
	s.auditLog(ctx, nil, "user.role_changed", map[string]interface{}{"target_user_id": userID, "new_role": role}, nil)
	return nil
}

func (s *authServiceImpl) UpdateUserMetadata(ctx context.Context, userID uuid.UUID, metadata map[string]interface{}) error {
	s.logger.WithFields(logrus.Fields{"user_id": userID}).Info("Updating user metadata")

	if err := s.userRepo.UpdateMetadata(ctx, userID, metadata); err != nil {
		return fmt.Errorf("failed to update user metadata: %w", err)
	}
	return nil
}

func (s *authServiceImpl) ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error) {
	filter := repo.ListUsersFilter{
		Page:     req.Page,
		PageSize: req.PageSize,
		Search:   req.Search,
		Role:     req.Role,
		IsActive: req.IsActive,
	}

	users, total, err := s.userRepo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	pageSize := filter.PageSize
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}

	return &ListUsersResponse{
		Users:      users,
		Total:      total,
		Page:       filter.Page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func (s *authServiceImpl) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]domain.SessionInfo, error) {
	sessions, err := s.redisRepo.ListUserSessions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	return sessions, nil
}

func (s *authServiceImpl) RevokeUserSession(ctx context.Context, userID uuid.UUID, jti string) error {
	exists, err := s.redisRepo.GetRefreshToken(ctx, userID, jti)
	if err != nil {
		return fmt.Errorf("failed to check session: %w", err)
	}
	if !exists {
		return fmt.Errorf("session not found")
	}

	if err := s.redisRepo.DeleteRefreshToken(ctx, userID, jti); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"jti":     jti,
	}).Info("Session revoked")
	return nil
}

// WithAuditActor returns a context-aware wrapper that stamps actorID + IP into audit logs.
// Call this from the handler after extracting admin context: svc.AuditAdminAction(ctx, adminID, event, data, ip)
func (s *authServiceImpl) AuditAdminAction(ctx context.Context, adminID uuid.UUID, eventType string, data map[string]interface{}, ip string) {
	actor := &adminID
	var ipPtr *string
	if ip != "" {
		ipPtr = &ip
	}
	s.auditLog(ctx, actor, eventType, data, ipPtr)
}

