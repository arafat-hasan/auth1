package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"auth1/internal/app/model/domain"
)

type RedisRepository interface {
	// OTP operations
	SetOTP(ctx context.Context, email, purpose, hashedOTP string, ttl time.Duration) error
	GetOTP(ctx context.Context, email, purpose string) (string, error)
	DeleteOTP(ctx context.Context, email, purpose string) error
	OTPExists(ctx context.Context, email, purpose string) (bool, error)

	// Pending user operations
	SetPendingUser(ctx context.Context, email string, user *domain.PendingUser, ttl time.Duration) error
	GetPendingUser(ctx context.Context, email string) (*domain.PendingUser, error)
	DeletePendingUser(ctx context.Context, email string) error

	// Refresh token operations
	SetRefreshToken(ctx context.Context, userID uuid.UUID, jti string, ttl time.Duration) error
	GetRefreshToken(ctx context.Context, userID uuid.UUID, jti string) (bool, error)
	DeleteRefreshToken(ctx context.Context, userID uuid.UUID, jti string) error
	DeleteAllRefreshTokens(ctx context.Context, userID uuid.UUID) error

	// 2FA secret operations
	SetTOTPSecret(ctx context.Context, userID uuid.UUID, secret string, ttl time.Duration) error
	GetTOTPSecret(ctx context.Context, userID uuid.UUID) (string, error)
	DeleteTOTPSecret(ctx context.Context, userID uuid.UUID) error
}

type redisRepository struct {
	client *redis.Client
}

func NewRedisRepository(client *redis.Client) RedisRepository {
	return &redisRepository{client: client}
}

// OTP operations
func (r *redisRepository) SetOTP(ctx context.Context, email, purpose, hashedOTP string, ttl time.Duration) error {
	key := fmt.Sprintf("otp:%s:%s", email, purpose)
	return r.client.Set(ctx, key, hashedOTP, ttl).Err()
}

func (r *redisRepository) GetOTP(ctx context.Context, email, purpose string) (string, error) {
	key := fmt.Sprintf("otp:%s:%s", email, purpose)
	result, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}
	return result, nil
}

func (r *redisRepository) DeleteOTP(ctx context.Context, email, purpose string) error {
	key := fmt.Sprintf("otp:%s:%s", email, purpose)
	return r.client.Del(ctx, key).Err()
}

func (r *redisRepository) OTPExists(ctx context.Context, email, purpose string) (bool, error) {
	key := fmt.Sprintf("otp:%s:%s", email, purpose)
	result, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

// Pending user operations
func (r *redisRepository) SetPendingUser(ctx context.Context, email string, user *domain.PendingUser, ttl time.Duration) error {
	key := fmt.Sprintf("pending_user:%s", email)
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal pending user: %w", err)
	}
	return r.client.Set(ctx, key, data, ttl).Err()
}

func (r *redisRepository) GetPendingUser(ctx context.Context, email string) (*domain.PendingUser, error) {
	key := fmt.Sprintf("pending_user:%s", email)
	result, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var user domain.PendingUser
	if err := json.Unmarshal([]byte(result), &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pending user: %w", err)
	}

	return &user, nil
}

func (r *redisRepository) DeletePendingUser(ctx context.Context, email string) error {
	key := fmt.Sprintf("pending_user:%s", email)
	return r.client.Del(ctx, key).Err()
}

// Refresh token operations
func (r *redisRepository) SetRefreshToken(ctx context.Context, userID uuid.UUID, jti string, ttl time.Duration) error {
	key := fmt.Sprintf("refresh_token:%s:%s", userID.String(), jti)
	return r.client.Set(ctx, key, "valid", ttl).Err()
}

func (r *redisRepository) GetRefreshToken(ctx context.Context, userID uuid.UUID, jti string) (bool, error) {
	key := fmt.Sprintf("refresh_token:%s:%s", userID.String(), jti)
	result, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

func (r *redisRepository) DeleteRefreshToken(ctx context.Context, userID uuid.UUID, jti string) error {
	key := fmt.Sprintf("refresh_token:%s:%s", userID.String(), jti)
	return r.client.Del(ctx, key).Err()
}

func (r *redisRepository) DeleteAllRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	pattern := fmt.Sprintf("refresh_token:%s:*", userID.String())
	keys, err := r.client.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return r.client.Del(ctx, keys...).Err()
	}

	return nil
}

// 2FA secret operations
func (r *redisRepository) SetTOTPSecret(ctx context.Context, userID uuid.UUID, secret string, ttl time.Duration) error {
	key := fmt.Sprintf("2fa_secret:%s", userID.String())
	return r.client.Set(ctx, key, secret, ttl).Err()
}

func (r *redisRepository) GetTOTPSecret(ctx context.Context, userID uuid.UUID) (string, error) {
	key := fmt.Sprintf("2fa_secret:%s", userID.String())
	result, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}
	return result, nil
}

func (r *redisRepository) DeleteTOTPSecret(ctx context.Context, userID uuid.UUID) error {
	key := fmt.Sprintf("2fa_secret:%s", userID.String())
	return r.client.Del(ctx, key).Err()
}
