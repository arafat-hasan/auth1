package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// Rule names one of the Redis limits of TDD-07 §2. It is the limit's key under rate_limits, the
// rule label of auth1_rate_limited_total and the rule segment of the Redis key.
type Rule string

// The Redis limits (TDD-07 §2, §8). Every rule but RuleTokenClient is keyed by the client IP.
const (
	RuleGlobalIP       Rule = "global_ip"       // L-1: every public API request
	RuleSignInIP       Rule = "sign_in_ip"      // L-2: sign-in attempts
	RuleRegistrationIP Rule = "registration_ip" // L-4: registrations
	RuleResetIP        Rule = "reset_ip"        // L-5: reset requests
	RuleSendIP         Rule = "send_ip"         // L-8: codes and links sent
	RuleVerifyIP       Rule = "verify_ip"       // L-12: verification attempts (codes and links)
	RuleResumeIP       Rule = "resume_ip"       // L-14: resume requests
	RuleTokenClient    Rule = "token_client"    // L-15: client-credentials tokens, by client id
)

// Rules returns every Rule, in the order of TDD-07 §2.
func Rules() []Rule {
	return []Rule{
		RuleGlobalIP, RuleSignInIP, RuleRegistrationIP, RuleResetIP,
		RuleSendIP, RuleVerifyIP, RuleResumeIP, RuleTokenClient,
	}
}

// RateLimit is at most Limit hits in any Window.
type RateLimit struct {
	Limit  int
	Window time.Duration
}

// RateDecision is the outcome of one hit. A refused hit has RetryAfter > 0: the time until the
// window has room again.
type RateDecision struct {
	Allowed    bool
	RetryAfter time.Duration
}

// RateLimiter counts hits in sliding windows (TDD-07 §8). Hit counts one hit for key under rule
// when the window has room, and refuses it otherwise; a refused hit is not counted. An error means
// the store failed, and says nothing about the limit.
type RateLimiter interface {
	Hit(ctx context.Context, rule Rule, key string, limit RateLimit) (RateDecision, error)
}

// RateLimits applies the Redis limits for the middleware and the use cases. Per TDD-07 §8 it fails
// open: when the limiter errs, the hit is allowed (the adapter records the error).
type RateLimits struct {
	limiter RateLimiter
	rules   map[Rule]RateLimit
}

// NewRateLimits returns the limits of rules over limiter. rules must hold every Rule and nothing
// else, each with a Limit and a Window above zero (TDD-08 §3.1).
func NewRateLimits(limiter RateLimiter, rules map[Rule]RateLimit) (*RateLimits, error) {
	var errs []error
	for _, r := range Rules() {
		l, ok := rules[r]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("rate limit %s: missing", r))
		case l.Limit <= 0 || l.Window <= 0:
			errs = append(errs, fmt.Errorf("rate limit %s: limit and window must be above 0", r))
		}
	}
	for r := range rules {
		if !slices.Contains(Rules(), r) {
			errs = append(errs, fmt.Errorf("rate limit %s: unknown rule", r))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return &RateLimits{limiter: limiter, rules: rules}, nil
}

// Check counts one hit for key under rule. It returns a RATE_LIMITED *domain.Error carrying the
// retry time when the limit is reached, and nil when the hit is allowed or the limiter fails.
// Endpoints that always answer 202 (L-5, L-8 there, L-14) take the error as "silently not sent".
func (rl *RateLimits) Check(ctx context.Context, rule Rule, key string) error {
	limit, ok := rl.rules[rule]
	if !ok {
		return fmt.Errorf("rate limit %s: unknown rule", rule)
	}
	d, err := rl.limiter.Hit(ctx, rule, key, limit)
	if err != nil {
		return nil //nolint:nilerr // fail open (TDD-07 §8); the adapter records the error
	}
	if d.Allowed {
		return nil
	}
	return &domain.Error{
		Code: domain.CodeRateLimited, Detail: "Too many requests; try again later.", RetryAfter: d.RetryAfter,
	}
}

// CheckIP is Check keyed by IPKey(ip). An invalid ip, which only a listener that is not TCP gives,
// has no key and is allowed.
func (rl *RateLimits) CheckIP(ctx context.Context, rule Rule, ip netip.Addr) error {
	key := IPKey(ip)
	if key == "" {
		return nil
	}
	return rl.Check(ctx, rule, key)
}

// IPKey is the limit key of ip (TDD-07 §1): an IPv4 address whole, an IPv6 address by its /64
// prefix. An IPv4-mapped IPv6 address is keyed as IPv4, and a zone is dropped. It is "" for an
// invalid ip.
func IPKey(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		return ip.String()
	}
	return netip.PrefixFrom(ip, 64).Masked().String()
}
