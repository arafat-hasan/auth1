package repo

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"auth1/internal/app/model/db"
	"auth1/internal/app/model/domain"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByPhone(ctx context.Context, phone string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	UpdateLastLogin(ctx context.Context, userID uuid.UUID) error
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
	Enable2FA(ctx context.Context, userID uuid.UUID, totpSecret string) error
	Disable2FA(ctx context.Context, userID uuid.UUID) error
	SetVerified(ctx context.Context, userID uuid.UUID) error
	EmailExists(ctx context.Context, email string) (bool, error)
	PhoneExists(ctx context.Context, phone string) (bool, error)
}

type userRepository struct {
	db *bun.DB
}

func NewUserRepository(db *bun.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	dbUser := &db.User{
		ID:           user.ID,
		Email:        user.Email,
		Name:         user.Name,
		Phone:        user.Phone,
		PasswordHash: user.PasswordHash,
		IsVerified:   user.IsVerified,
		Is2FAEnabled: user.Is2FAEnabled,
		TOTPSecret:   user.TOTPSecret,
		LastLoginAt:  user.LastLoginAt,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
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
	err := r.db.NewSelect().Model(dbUser).Where("email = ?", email).Scan(ctx)
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
	err := r.db.NewSelect().Model(dbUser).Where("id = ?", id).Scan(ctx)
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
	err := r.db.NewSelect().Model(dbUser).Where("phone = ?", phone).Scan(ctx)
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

func (r *userRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("last_login_at = ?, updated_at = ?", now, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.User)(nil)).
		Set("password_hash = ?, updated_at = ?", passwordHash, now).
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
		Set("is_verified = ?, updated_at = ?", true, now).
		Where("id = ?", userID).
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("failed to set user verified: %w", err)
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
		ID:           dbUser.ID,
		Email:        dbUser.Email,
		Name:         dbUser.Name,
		Phone:        dbUser.Phone,
		PasswordHash: dbUser.PasswordHash,
		IsVerified:   dbUser.IsVerified,
		Is2FAEnabled: dbUser.Is2FAEnabled,
		TOTPSecret:   dbUser.TOTPSecret,
		LastLoginAt:  dbUser.LastLoginAt,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
	}
}
