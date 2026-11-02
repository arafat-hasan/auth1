package main

import (
	goredis "github.com/redis/go-redis/v9"

	"github.com/arafat-hasan/auth1/internal/adapters/redis"
	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/telemetry"
)

// newRateLimits builds the Redis limits of TDD-07 §2 from rate_limits over a client for redis.
// The caller closes the client after the servers have stopped. It connects on first use, so serve
// starts while Redis is down; the limits then fail open.
func newRateLimits(cfg *config.Config, metrics *telemetry.Metrics) (*app.RateLimits, *goredis.Client, error) {
	limited, err := metrics.Counter("auth1_rate_limited_total")
	if err != nil {
		return nil, nil, err
	}
	failed, err := metrics.Counter("auth1_rate_limiter_errors_total")
	if err != nil {
		return nil, nil, err
	}
	client, err := redis.Open(cfg.Redis)
	if err != nil {
		return nil, nil, err
	}
	rl := cfg.RateLimits
	limit := func(l config.RateLimit) app.RateLimit { return app.RateLimit{Limit: l.Limit, Window: l.Window} }
	limits, err := app.NewRateLimits(redis.NewLimiter(client, redis.Options{
		Prefix: cfg.Redis.Prefix, Clock: system.Clock{}, Limited: limited, Errors: failed,
	}), map[app.Rule]app.RateLimit{
		app.RuleGlobalIP:       limit(rl.GlobalIP),
		app.RuleSignInIP:       limit(rl.SignInIP),
		app.RuleRegistrationIP: limit(rl.RegistrationIP),
		app.RuleResetIP:        limit(rl.ResetIP),
		app.RuleSendIP:         limit(rl.SendIP),
		app.RuleVerifyIP:       limit(rl.VerifyIP),
		app.RuleResumeIP:       limit(rl.ResumeIP),
		app.RuleTokenClient:    limit(rl.TokenClient),
	})
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	return limits, client, nil
}
