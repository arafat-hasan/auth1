package fakes

import (
	"context"
	"sync"

	"github.com/arafat-hasan/auth1/internal/app"
)

var _ app.RateLimiter = (*RateLimiter)(nil)

// RateLimiter counts hits per rule and key in memory, with no window: once a key has Limit hits,
// every further hit is refused with RetryAfter equal to the Window. It is safe for concurrent use.
type RateLimiter struct {
	mu   sync.Mutex
	hits map[app.Rule]map[string]int
	err  error
}

// NewRateLimiter returns a limiter with no hits.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{hits: map[app.Rule]map[string]int{}}
}

// Fail makes every later Hit return err; nil restores counting.
func (l *RateLimiter) Fail(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = err
}

// Hits returns the hits counted for key under rule.
func (l *RateLimiter) Hits(rule app.Rule, key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.hits[rule][key]
}

// Hit implements app.RateLimiter.
func (l *RateLimiter) Hit(_ context.Context, rule app.Rule, key string, limit app.RateLimit) (app.RateDecision, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return app.RateDecision{}, l.err
	}
	if l.hits[rule] == nil {
		l.hits[rule] = map[string]int{}
	}
	if l.hits[rule][key] >= limit.Limit {
		return app.RateDecision{RetryAfter: limit.Window}, nil
	}
	l.hits[rule][key]++
	return app.RateDecision{Allowed: true}, nil
}
