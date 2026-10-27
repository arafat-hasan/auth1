package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter provides rate limiting functionality using Redis
type RateLimiter struct {
	redis *redis.Client
}

// NewRateLimiter creates a new rate limiter instance
func NewRateLimiter(redis *redis.Client) *RateLimiter {
	return &RateLimiter{redis: redis}
}

// Result contains the result of a rate limit check
type Result struct {
	Allowed   bool
	Limit     int
	Remaining int
	ResetAt   time.Time
}

// Allow checks if a request is allowed under the rate limit
// Uses sliding window algorithm with Redis sorted sets
func (r *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (*Result, error) {
	now := time.Now()
	windowStart := now.Add(-window)

	// Use Redis pipeline for atomic operations
	pipe := r.redis.Pipeline()

	// Remove old entries outside the current window
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart.UnixNano()))

	// Count current requests in window
	countCmd := pipe.ZCount(ctx, key, fmt.Sprintf("%d", windowStart.UnixNano()), "+inf")

	// Add current request timestamp
	pipe.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: now.UnixNano(), // Use nano timestamp as unique member
	})

	// Set expiration (window + buffer)
	pipe.Expire(ctx, key, window+time.Minute)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("rate limiter redis error: %w", err)
	}

	// Get count from result
	count, err := countCmd.Result()
	if err != nil {
		return nil, fmt.Errorf("rate limiter count error: %w", err)
	}

	// Check if allowed (count before adding current request)
	allowed := count < int64(limit)

	// Calculate remaining
	remaining := limit - int(count) - 1
	if remaining < 0 {
		remaining = 0
	}

	// Calculate reset time (oldest entry + window)
	resetAt := r.getResetTime(ctx, key, window)

	return &Result{
		Allowed:   allowed,
		Limit:     limit,
		Remaining: remaining,
		ResetAt:   resetAt,
	}, nil
}

// AllowN checks if N requests are allowed under the rate limit
// Useful for batch operations
func (r *RateLimiter) AllowN(ctx context.Context, key string, limit int, window time.Duration, n int) (*Result, error) {
	if n <= 0 {
		n = 1
	}

	now := time.Now()
	windowStart := now.Add(-window)

	pipe := r.redis.Pipeline()

	// Remove old entries
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart.UnixNano()))

	// Count current requests
	countCmd := pipe.ZCount(ctx, key, fmt.Sprintf("%d", windowStart.UnixNano()), "+inf")

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("rate limiter redis error: %w", err)
	}

	count, err := countCmd.Result()
	if err != nil {
		return nil, fmt.Errorf("rate limiter count error: %w", err)
	}

	// Check if N requests are allowed
	allowed := (count + int64(n)) <= int64(limit)

	if allowed {
		// Add N entries
		pipe2 := r.redis.Pipeline()
		for i := 0; i < n; i++ {
			timestamp := now.Add(time.Duration(i) * time.Nanosecond)
			pipe2.ZAdd(ctx, key, redis.Z{
				Score:  float64(timestamp.UnixNano()),
				Member: timestamp.UnixNano(),
			})
		}
		pipe2.Expire(ctx, key, window+time.Minute)
		_, err = pipe2.Exec(ctx)
		if err != nil {
			return nil, fmt.Errorf("rate limiter add error: %w", err)
		}
	}

	remaining := limit - int(count) - n
	if remaining < 0 {
		remaining = 0
	}

	resetAt := r.getResetTime(ctx, key, window)

	return &Result{
		Allowed:   allowed,
		Limit:     limit,
		Remaining: remaining,
		ResetAt:   resetAt,
	}, nil
}

// Remaining returns the number of remaining requests
func (r *RateLimiter) Remaining(ctx context.Context, key string, limit int, window time.Duration) (int, error) {
	now := time.Now()
	windowStart := now.Add(-window)

	count, err := r.redis.ZCount(ctx, key, fmt.Sprintf("%d", windowStart.UnixNano()), "+inf").Result()
	if err != nil {
		return 0, fmt.Errorf("rate limiter remaining error: %w", err)
	}

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	return remaining, nil
}

// Reset resets the rate limit for a key
func (r *RateLimiter) Reset(ctx context.Context, key string) error {
	return r.redis.Del(ctx, key).Err()
}

// ResetAt returns when the rate limit will reset
func (r *RateLimiter) ResetAt(ctx context.Context, key string, window time.Duration) (time.Time, error) {
	return r.getResetTime(ctx, key, window), nil
}

// getResetTime calculates when the rate limit will reset
func (r *RateLimiter) getResetTime(ctx context.Context, key string, window time.Duration) time.Time {
	// Get the oldest entry in the window
	results, err := r.redis.ZRangeWithScores(ctx, key, 0, 0).Result()
	if err != nil || len(results) == 0 {
		// No entries, reset time is now + window
		return time.Now().Add(window)
	}

	// Reset time is oldest entry + window
	oldestTimestamp := int64(results[0].Score)
	oldestTime := time.Unix(0, oldestTimestamp)
	resetTime := oldestTime.Add(window)

	// If reset time is in the past, return now + window
	if resetTime.Before(time.Now()) {
		return time.Now().Add(window)
	}

	return resetTime
}

// GetInfo returns current rate limit information without incrementing
func (r *RateLimiter) GetInfo(ctx context.Context, key string, limit int, window time.Duration) (*Result, error) {
	now := time.Now()
	windowStart := now.Add(-window)

	// Clean up old entries and count
	pipe := r.redis.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart.UnixNano()))
	countCmd := pipe.ZCount(ctx, key, fmt.Sprintf("%d", windowStart.UnixNano()), "+inf")

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("rate limiter info error: %w", err)
	}

	count, err := countCmd.Result()
	if err != nil {
		return nil, fmt.Errorf("rate limiter count error: %w", err)
	}

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	resetAt := r.getResetTime(ctx, key, window)

	return &Result{
		Allowed:   remaining > 0,
		Limit:     limit,
		Remaining: remaining,
		ResetAt:   resetAt,
	}, nil
}
