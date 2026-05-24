package repo

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/app/model/db"
	"github.com/arafat-hasan/auth1/internal/app/model/domain"
)

// ListUsersFilter holds optional filter parameters for listing users.
type ListUsersFilter struct {
	Page     int
	PageSize int
	Search   string // email or name ILIKE
	Role     string
	IsActive *bool
}

type UserRepository interface {
	// Basic CRUD
	Create(ctx context.Context, user *domain.User) error
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByPhone(ctx context.Context, phone string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	SoftDelete(ctx context.Context, userID uuid.UUID) error
	List(ctx context.Context, filter ListUsersFilter) ([]*domain.User, int, error)
	
	// Authentication tracking
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, ipAddress, userAgent *string) error
	IncrementFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error
	ResetFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error
	LockAccount(ctx context.Context, userID uuid.UUID, lockUntil time.Time) error
	UnlockAccount(ctx context.Context, userID uuid.UUID) error
	
	// Password management
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	SetPasswordResetTimestamp(ctx context.Context, userID uuid.UUID) error
	SetMustChangePassword(ctx context.Context, userID uuid.UUID, mustChange bool) error
	
	// 2FA management
	Enable2FA(ctx context.Context, userID uuid.UUID, totpSecret string) error
	Disable2FA(ctx context.Context, userID uuid.UUID) error
	
	// Verification
	SetEmailVerified(ctx context.Context, userID uuid.UUID) error
	SetPhoneVerified(ctx context.Context, userID uuid.UUID) error
	SetVerified(ctx context.Context, userID uuid.UUID) error
	
	// Account status
	SetActiveStatus(ctx context.Context, userID uuid.UUID, isActive bool) error
	
	// Role management
	UpdateRole(ctx context.Context, userID uuid.UUID, role string) error
	
	// Metadata management
	UpdateMetadata(ctx context.Context, userID uuid.UUID, metadata map[string]interface{}) error
	
	// Existence checks
	EmailExists(ctx context.Context, email string) (bool, error)
	PhoneExists(ctx context.Context, phone string) (bool, error)
	
	// Password reset tokens
	CreatePasswordResetToken(ctx context.Context, token *db.PasswordResetToken) error
	GetPasswordResetToken(ctx context.Context, tokenHash string) (*db.PasswordResetToken, error)
	MarkPasswordResetTokenAsUsed(ctx context.Context, tokenID uuid.UUID) error
	
	// Audit logging
	LogAuditEvent(ctx context.Context, actorID *uuid.UUID, eventType string, data map[string]interface{}, ip *string) error
}

type userRepository struct {
	db *bun.DB
}

func NewUserRepository(db *bun.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	now := time.Now()
	dbUser := &db.User{
		ID:                  user.ID,
		Email:               user.Email,
		Name:                user.Name,
		Phone:               user.Phone,
		PasswordHash:        user.PasswordHash,
		IsVerified:          user.IsVerified,
		IsActive:            user.IsActive,
		EmailVerifiedAt:     user.EmailVerifiedAt,
		PhoneVerifiedAt:     user.PhoneVerifiedAt,
		Is2FAEnabled:        user.Is2FAEnabled,
		TOTPSecret:          user.TOTPSecret,
		FailedLoginAttempts: user.FailedLoginAttempts,
		LockedUntil:         user.LockedUntil,
		PasswordChangedAt:   user.PasswordChangedAt,
		MustChangePassword:  user.MustChangePassword,
		LastPasswordResetAt: user.LastPasswordResetAt,
		Role:                user.Role,
		Metadata:            db.Metadata(user.Metadata),
		LastLoginAt:         user.LastLoginAt,
		IPAddress:           user.IPAddress,
		UserAgent:           user.UserAgent,
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	_, err := r.db.NewInsert().Model(dbUser).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	user.CreatedAt = dbUser.CreatedAt
	user.UpdatedAt = dbUser.UpdatedAt

	return nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	dbUser := &db.User{}
	err := r.db.NewSelect().Model(dbUser).
		Where("email = ?", email).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return r.toDomainUser(dbUser), nil
}

func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	dbUser := &db.User{}
	err := r.db.NewSelect().Model(dbUser).
		Where("id = ?", id).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return r.toDomainUser(dbUser), nil
}

func (r *userRepository) GetByPhone(ctx context.Context, phone string) (*domain.User, error) {
	dbUser := &db.User{}
	err := r.db.NewSelect().Model(dbUser).
		Where("phone = ?", phone).
		Where("deleted_at IS NULL").
		Scan(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by phone: %w", err)
	}

	return r.toDomainUser(dbUser), nil
}

func (r *userRepository) Update(ctx context.Context, user *domain.User) error {
	dbUser := &db.User{
		ID:           user.ID,
		Email:        user.Email,
		Phone:        user.Phone,
		PasswordHash: user.PasswordHash,
		IsVerified:   user.IsVerified,
		Is2FAEnabled: user.Is2FAEnabled,
		TOTPSecret:   user.TOTPSecret,
		LastLoginAt:  user.LastLoginAt,
		UpdatedAt:    time.Now(),
	}

	_, err := r.db.NewUpdate().Model(dbUser).Where("id = ?", user.ID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	user.UpdatedAt = dbUser.UpdatedAt

	return nil
}

func (r *userRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID, ipAddress, userAgent *string) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("last_login_at = ?, ip_address = ?, user_agent = ?, updated_at = ?", now, ipAddress, userAgent, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

func (r *userRepository) IncrementFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("failed_login_attempts = failed_login_attempts + 1, updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to increment failed login attempts: %w", err)
	}

	return nil
}

func (r *userRepository) ResetFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("failed_login_attempts = 0, updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to reset failed login attempts: %w", err)
	}

	return nil
}

func (r *userRepository) LockAccount(ctx context.Context, userID uuid.UUID, lockUntil time.Time) error {
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("locked_until = ?, updated_at = ?", lockUntil, time.Now()).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to lock account: %w", err)
	}

	return nil
}

func (r *userRepository) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("locked_until = NULL, failed_login_attempts = 0, updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}

	return nil
}

func (r *userRepository) SoftDelete(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("deleted_at = ?, is_active = ?, updated_at = ?", now, false, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to soft delete user: %w", err)
	}

	return nil
}

func (r *userRepository) SetPasswordResetTimestamp(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("last_password_reset_at = ?, updated_at = ?", now, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to set password reset timestamp: %w", err)
	}

	return nil
}

func (r *userRepository) SetMustChangePassword(ctx context.Context, userID uuid.UUID, mustChange bool) error {
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("must_change_password = ?, updated_at = ?", mustChange, time.Now()).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to set must change password: %w", err)
	}

	return nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("password_hash = ?, password_changed_at = ?, must_change_password = ?, updated_at = ?", passwordHash, now, false, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

func (r *userRepository) Enable2FA(ctx context.Context, userID uuid.UUID, totpSecret string) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("is_2fa_enabled = ?, totp_secret = ?, updated_at = ?", true, totpSecret, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to enable 2FA: %w", err)
	}

	return nil
}

func (r *userRepository) Disable2FA(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("is_2fa_enabled = ?, totp_secret = ?, updated_at = ?", false, nil, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to disable 2FA: %w", err)
	}

	return nil
}

func (r *userRepository) SetVerified(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("is_verified = ?, email_verified_at = ?, updated_at = ?", true, now, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to set user verified: %w", err)
	}

	return nil
}

func (r *userRepository) SetEmailVerified(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("is_verified = ?, email_verified_at = ?, updated_at = ?", true, now, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to set email verified: %w", err)
	}

	return nil
}

func (r *userRepository) SetPhoneVerified(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("phone_verified_at = ?, updated_at = ?", now, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to set phone verified: %w", err)
	}

	return nil
}

func (r *userRepository) SetActiveStatus(ctx context.Context, userID uuid.UUID, isActive bool) error {
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("is_active = ?, updated_at = ?", isActive, time.Now()).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to set active status: %w", err)
	}

	return nil
}

func (r *userRepository) UpdateRole(ctx context.Context, userID uuid.UUID, role string) error {
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("role = ?, updated_at = ?", role, time.Now()).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	return nil
}

func (r *userRepository) UpdateMetadata(ctx context.Context, userID uuid.UUID, metadata map[string]interface{}) error {
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("metadata = ?, updated_at = ?", db.Metadata(metadata), time.Now()).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to update metadata: %w", err)
	}

	return nil
}

func (r *userRepository) CreatePasswordResetToken(ctx context.Context, token *db.PasswordResetToken) error {
	_, err := r.db.NewInsert().Model(token).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create password reset token: %w", err)
	}
	return nil
}

func (r *userRepository) GetPasswordResetToken(ctx context.Context, tokenHash string) (*db.PasswordResetToken, error) {
	token := &db.PasswordResetToken{}
	err := r.db.NewSelect().Model(token).
		Where("token_hash = ?", tokenHash).
		Where("used_at IS NULL").
		Where("expires_at > ?", time.Now()).
		Scan(ctx)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get password reset token: %w", err)
	}

	return token, nil
}

func (r *userRepository) MarkPasswordResetTokenAsUsed(ctx context.Context, tokenID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.PasswordResetToken)(nil)).
		Set("used_at = ?", now).
		Where("id = ?", tokenID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to mark password reset token as used: %w", err)
	}

	return nil
}

func (r *userRepository) List(ctx context.Context, filter ListUsersFilter) ([]*domain.User, int, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 || filter.PageSize > 100 {
		filter.PageSize = 20
	}
	offset := (filter.Page - 1) * filter.PageSize

	var dbUsers []db.User
	q := r.db.NewSelect().Model(&dbUsers).Where("u.deleted_at IS NULL")

	if filter.Search != "" {
		q = q.Where("(u.email ILIKE ? OR u.name ILIKE ?)", "%"+filter.Search+"%", "%"+filter.Search+"%")
	}
	if filter.Role != "" {
		q = q.Where("u.role = ?", filter.Role)
	}
	if filter.IsActive != nil {
		q = q.Where("u.is_active = ?", *filter.IsActive)
	}

	total, err := q.Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	err = q.OrderExpr("u.created_at DESC").Limit(filter.PageSize).Offset(offset).Scan(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	users := make([]*domain.User, len(dbUsers))
	for i := range dbUsers {
		users[i] = r.toDomainUser(&dbUsers[i])
	}
	return users, total, nil
}

func (r *userRepository) LogAuditEvent(ctx context.Context, actorID *uuid.UUID, eventType string, data map[string]interface{}, ip *string) error {
	entry := &db.AuditLog{
		ID:        uuid.New(),
		UserID:    actorID,
		EventType: eventType,
		EventData: db.Metadata(data),
		IPAddress: ip,
		CreatedAt: time.Now(),
	}
	_, err := r.db.NewInsert().Model(entry).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to write audit log: %w", err)
	}
	return nil
}

func (r *userRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	count, err := r.db.NewSelect().
		Model((*db.User)(nil)).
		Where("email = ?", email).
		Count(ctx)

	if err != nil {
		return false, fmt.Errorf("failed to check email existence: %w", err)
	}

	return count > 0, nil
}

func (r *userRepository) PhoneExists(ctx context.Context, phone string) (bool, error) {
	count, err := r.db.NewSelect().
		Model((*db.User)(nil)).
		Where("phone = ?", phone).
		Count(ctx)

	if err != nil {
		return false, fmt.Errorf("failed to check phone existence: %w", err)
	}

	return count > 0, nil
}

func (r *userRepository) toDomainUser(dbUser *db.User) *domain.User {
	return &domain.User{
		ID:                  dbUser.ID,
		Email:               dbUser.Email,
		Name:                dbUser.Name,
		Phone:               dbUser.Phone,
		PasswordHash:        dbUser.PasswordHash,
		IsVerified:          dbUser.IsVerified,
		IsActive:            dbUser.IsActive,
		EmailVerifiedAt:     dbUser.EmailVerifiedAt,
		PhoneVerifiedAt:     dbUser.PhoneVerifiedAt,
		DeletedAt:           dbUser.DeletedAt,
		Is2FAEnabled:        dbUser.Is2FAEnabled,
		TOTPSecret:          dbUser.TOTPSecret,
		FailedLoginAttempts: dbUser.FailedLoginAttempts,
		LockedUntil:         dbUser.LockedUntil,
		PasswordChangedAt:   dbUser.PasswordChangedAt,
		MustChangePassword:  dbUser.MustChangePassword,
		LastPasswordResetAt: dbUser.LastPasswordResetAt,
		Role:                dbUser.Role,
		Metadata:            map[string]interface{}(dbUser.Metadata),
		LastLoginAt:         dbUser.LastLoginAt,
		IPAddress:           dbUser.IPAddress,
		UserAgent:           dbUser.UserAgent,
		CreatedAt:           dbUser.CreatedAt,
		UpdatedAt:           dbUser.UpdatedAt,
	}
}
