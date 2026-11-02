package redis

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/arafat-hasan/auth1/internal/config"
)

// callTimeout bounds every Redis operation, dial included. A limiter that cannot answer within it
// fails open (TDD-07 §8), so a slow or unreachable Redis adds at most this to a request.
const callTimeout = 100 * time.Millisecond

// Open returns a client for cfg, with the password read from redis.password_file when it is set.
// It connects on first use, so serve starts while Redis is down, and never retries: a failed call
// fails open at once.
func Open(cfg config.Redis) (*goredis.Client, error) {
	o := &goredis.Options{
		Addr:                  cfg.Address,
		DialTimeout:           callTimeout,
		ReadTimeout:           callTimeout,
		WriteTimeout:          callTimeout,
		PoolTimeout:           callTimeout,
		ContextTimeoutEnabled: true,
		MaxRetries:            -1,
	}
	if cfg.PasswordFile.IsSet() {
		raw, err := os.ReadFile(cfg.PasswordFile.Path())
		if err != nil {
			return nil, fmt.Errorf("read redis.password_file: %w", err)
		}
		o.Password = string(bytes.TrimSpace(raw))
	}
	return goredis.NewClient(o), nil
}

// Ping returns the /readyz check of c, bounded by timeout.
func Ping(c *goredis.Client, timeout time.Duration) func(context.Context) error {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return c.Ping(ctx).Err()
	}
}
