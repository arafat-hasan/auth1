package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/arafat-hasan/auth1/internal/app/model/domain"
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
	SetRefreshToken(ctx context.Context, userID uuid.UUID, jti, ip, ua string, ttl time.Duration) error
	GetRefreshToken(ctx context.Context, userID uuid.UUID, jti string) (bool, error)
	DeleteRefreshToken(ctx context.Context, userID uuid.UUID, jti string) error
	DeleteAllRefreshTokens(ctx context.Context, userID uuid.UUID) error
	ListUserSessions(ctx context.Context, userID uuid.UUID) ([]domain.SessionInfo, error)

	// 2FA secret operations (temp storage during setup)
	SetTOTPSecret(ctx context.Context, userID uuid.UUID, secret string, ttl time.Duration) error
	GetTOTPSecret(ctx context.Context, userID uuid.UUID) (string, error)
	DeleteTOTPSecret(ctx context.Context, userID uuid.UUID) error

	// 2FA login challenge token operations (single-use, short TTL, issued after password auth)
	StoreTwoFAChallenge(ctx context.Context, token string, userID uuid.UUID, ttl time.Duration) error
	GetTwoFAChallenge(ctx context.Context, token string) (uuid.UUID, error)
	DeleteTwoFAChallenge(ctx context.Context, token string) error

	// JWT Blacklist operations (P0 - Week 1)
	BlacklistJWT(ctx context.Context, jti string, expiresAt time.Time) error
	IsJWTBlacklisted(ctx context.Context, jti string) (bool, error)
	BlacklistAllUserJWTs(ctx context.Context, userID uuid.UUID, ttl time.Duration) error
	IsUserTokensBlacklisted(ctx context.Context, userID string) (int64, error)

	// Login attempt tracking operations (P0 - Week 1)
	IncrementLoginAttempts(ctx context.Context, identifier, identifierType string) (int64, error)
	GetLoginAttempts(ctx context.Context, identifier, identifierType string) (int64, error)
	ResetLoginAttempts(ctx context.Context, identifier, identifierType string) error
	IsAccountLocked(ctx context.Context, identifier, identifierType string) (bool, time.Time, error)
	LockAccount(ctx context.Context, identifier, identifierType string, duration time.Duration) error
	GetLoginAttemptDetails(ctx context.Context, identifier, identifierType string) (map[string]string, error)
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
func (r *redisRepository) SetRefreshToken(ctx context.Context, userID uuid.UUID, jti, ip, ua string, ttl time.Duration) error {
	key := fmt.Sprintf("refresh_token:%s:%s", userID.String(), jti)
	pipe := r.client.Pipeline()
	pipe.HSet(ctx, key, "ip", ip, "ua", ua, "created_at", time.Now().Unix())
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
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

// ListUserSessions returns metadata for every active session (refresh token) for the user.
func (r *redisRepository) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]domain.SessionInfo, error) {
	pattern := fmt.Sprintf("refresh_token:%s:*", userID.String())
	var sessions []domain.SessionInfo
	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		// key format: refresh_token:{userID}:{jti}
		parts := strings.SplitN(key, ":", 3)
		if len(parts) != 3 {
			continue
		}
		fields, err := r.client.HGetAll(ctx, key).Result()
		if err != nil {
			continue
		}
		info := domain.SessionInfo{JTI: parts[2]}
		info.IPAddress = fields["ip"]
		info.UserAgent = fields["ua"]
		if ts, ok := fields["created_at"]; ok {
			if unix, err := strconv.ParseInt(ts, 10, 64); err == nil {
				info.CreatedAt = time.Unix(unix, 0)
			}
		}
		sessions = append(sessions, info)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	return sessions, nil
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

// JWT Blacklist operations

// BlacklistJWT adds a JWT token to the blacklist
// The token will be blacklisted for its remaining lifetime
func (r *redisRepository) BlacklistJWT(ctx context.Context, jti string, expiresAt time.Time) error {
	// Calculate remaining TTL
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	key := fmt.Sprintf("blacklist:jwt:%s", jti)
	return r.client.Set(ctx, key, "1", ttl).Err()
}

// IsJWTBlacklisted checks if a JWT token is blacklisted
func (r *redisRepository) IsJWTBlacklisted(ctx context.Context, jti string) (bool, error) {
	key := fmt.Sprintf("blacklist:jwt:%s", jti)
	result, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

// BlacklistAllUserJWTs blacklists all JWTs for a specific user
// This is useful when a user changes their password or is compromised
// Note: We use a user-level blacklist marker that's checked in addition to individual JTI
func (r *redisRepository) BlacklistAllUserJWTs(ctx context.Context, userID uuid.UUID, ttl time.Duration) error {
	key := fmt.Sprintf("blacklist:user:%s", userID.String())
	timestamp := time.Now().Unix()
	// Store the timestamp when all tokens were invalidated
	return r.client.Set(ctx, key, timestamp, ttl).Err()
}

// IsUserTokensBlacklisted checks if all tokens for a user have been blacklisted
// Returns the timestamp when tokens were blacklisted, or 0 if not blacklisted
func (r *redisRepository) IsUserTokensBlacklisted(ctx context.Context, userID string) (int64, error) {
	key := fmt.Sprintf("blacklist:user:%s", userID)
	result, err := r.client.Get(ctx, key).Int64()
	if err != nil {
		if err == redis.Nil {
			return 0, nil // Not blacklisted
		}
		return 0, err
	}
	return result, nil
}

// Login attempt tracking operations

// IncrementLoginAttempts increments the failed login attempt counter
// Returns the new count
func (r *redisRepository) IncrementLoginAttempts(ctx context.Context, identifier, identifierType string) (int64, error) {
	key := fmt.Sprintf("login_attempts:%s:%s", identifierType, identifier)

	// Use pipeline for atomic operations
	pipe := r.client.Pipeline()

	// Increment count
	incrCmd := pipe.HIncrBy(ctx, key, "count", 1)

	// Set first attempt time if not exists
	pipe.HSetNX(ctx, key, "first_attempt_at", time.Now().Unix())

	// Update last attempt time
	pipe.HSet(ctx, key, "last_attempt_at", time.Now().Unix())

	// Set expiration (30 minutes from now)
	pipe.Expire(ctx, key, 30*time.Minute)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return incrCmd.Val(), nil
}

// GetLoginAttempts returns the current number of failed login attempts
func (r *redisRepository) GetLoginAttempts(ctx context.Context, identifier, identifierType string) (int64, error) {
	key := fmt.Sprintf("login_attempts:%s:%s", identifierType, identifier)

	count, err := r.client.HGet(ctx, key, "count").Int64()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, err
	}

	return count, nil
}

// ResetLoginAttempts resets the login attempt counter (called on successful login)
func (r *redisRepository) ResetLoginAttempts(ctx context.Context, identifier, identifierType string) error {
	key := fmt.Sprintf("login_attempts:%s:%s", identifierType, identifier)
	return r.client.Del(ctx, key).Err()
}

// IsAccountLocked checks if an account is currently locked
// Returns: locked (bool), unlockTime (time.Time), error
func (r *redisRepository) IsAccountLocked(ctx context.Context, identifier, identifierType string) (bool, time.Time, error) {
	key := fmt.Sprintf("login_attempts:%s:%s", identifierType, identifier)

	lockedUntil, err := r.client.HGet(ctx, key, "locked_until").Int64()
	if err != nil {
		if err == redis.Nil {
			return false, time.Time{}, nil
		}
		return false, time.Time{}, err
	}

	unlockTime := time.Unix(lockedUntil, 0)

	// Check if still locked
	if unlockTime.After(time.Now()) {
		return true, unlockTime, nil
	}

	return false, time.Time{}, nil
}

// LockAccount locks an account for a specified duration
func (r *redisRepository) LockAccount(ctx context.Context, identifier, identifierType string, duration time.Duration) error {
	key := fmt.Sprintf("login_attempts:%s:%s", identifierType, identifier)

	lockUntil := time.Now().Add(duration).Unix()

	pipe := r.client.Pipeline()
	pipe.HSet(ctx, key, "locked_until", lockUntil)
	pipe.HSet(ctx, key, "locked_at", time.Now().Unix())
	pipe.Expire(ctx, key, duration+time.Minute) // TTL slightly longer than lock duration

	_, err := pipe.Exec(ctx)
	return err
}

// GetLoginAttemptDetails returns all details about login attempts
// Useful for logging and debugging
func (r *redisRepository) GetLoginAttemptDetails(ctx context.Context, identifier, identifierType string) (map[string]string, error) {
	key := fmt.Sprintf("login_attempts:%s:%s", identifierType, identifier)

	result, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return make(map[string]string), nil
		}
		return nil, err
	}

	return result, nil
}

// 2FA login challenge token operations

func (r *redisRepository) StoreTwoFAChallenge(ctx context.Context, token string, userID uuid.UUID, ttl time.Duration) error {
	key := fmt.Sprintf("2fa_challenge:%s", token)
	return r.client.Set(ctx, key, userID.String(), ttl).Err()
}

func (r *redisRepository) GetTwoFAChallenge(ctx context.Context, token string) (uuid.UUID, error) {
	key := fmt.Sprintf("2fa_challenge:%s", token)
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return uuid.Nil, nil
		}
		return uuid.Nil, err
	}
	return uuid.Parse(val)
}

func (r *redisRepository) DeleteTwoFAChallenge(ctx context.Context, token string) error {
	key := fmt.Sprintf("2fa_challenge:%s", token)
	return r.client.Del(ctx, key).Err()
}
