package redis

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/arafat-hasan/auth1/internal/app"
)

//go:embed limiter.lua
var hitLua string

var hitScript = goredis.NewScript(hitLua)

var _ app.RateLimiter = (*Limiter)(nil)

// Options are the limiter's dependencies.
type Options struct {
	Prefix  string              // redis.prefix
	Clock   app.Clock           // the window's time; replicas share it through NTP
	Limited metric.Int64Counter // auth1_rate_limited_total, by rule
	Errors  metric.Int64Counter // auth1_rate_limiter_errors_total
}

// Limiter is the sliding-window limiter of TDD-07 §8: a sorted set per rule and key at
// <prefix>rl:<rule>:<key>, holding one member per counted hit, scored by its time in microseconds.
// Each hit is one script run, so concurrent hits from many replicas count exactly.
type Limiter struct {
	c goredis.Scripter
	o Options
}

// NewLimiter returns a limiter on c.
func NewLimiter(c goredis.Scripter, o Options) *Limiter {
	return &Limiter{c: c, o: o}
}

// Hit implements app.RateLimiter. A refusal adds one to auth1_rate_limited_total{rule}; any Redis
// error adds one to auth1_rate_limiter_errors_total. Neither records the key (G-6).
func (l *Limiter) Hit(ctx context.Context, rule app.Rule, key string, limit app.RateLimit) (app.RateDecision, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	now := l.o.Clock.Now().UnixMicro()
	member, err := newMember(now)
	if err != nil {
		return app.RateDecision{}, err
	}
	retry, err := hitScript.Run(ctx, l.c, []string{l.o.Prefix + "rl:" + string(rule) + ":" + key},
		now, limit.Window.Microseconds(), limit.Limit, member).Int64()
	if err != nil {
		l.o.Errors.Add(context.WithoutCancel(ctx), 1)
		return app.RateDecision{}, fmt.Errorf("rate limiter: %w", err)
	}
	if retry == 0 {
		return app.RateDecision{Allowed: true}, nil
	}
	l.o.Limited.Add(ctx, 1, metric.WithAttributes(attribute.String("rule", string(rule))))
	return app.RateDecision{RetryAfter: time.Duration(retry) * time.Microsecond}, nil
}

// newMember returns a sorted-set member for a hit at now: the time and 8 random bytes, so hits in
// the same microsecond, on any replica, are distinct members.
func newMember(now int64) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("rate limiter: %w", err)
	}
	return strconv.FormatInt(now, 10) + ":" + hex.EncodeToString(b[:]), nil
}
