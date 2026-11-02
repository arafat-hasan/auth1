package app_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// rules gives every rule the same limit.
func rules(limit app.RateLimit) map[app.Rule]app.RateLimit {
	m := map[app.Rule]app.RateLimit{}
	for _, r := range app.Rules() {
		m[r] = limit
	}
	return m
}

func newLimits(t *testing.T, l app.RateLimiter, limit int) *app.RateLimits {
	t.Helper()
	rl, err := app.NewRateLimits(l, rules(app.RateLimit{Limit: limit, Window: time.Minute}))
	if err != nil {
		t.Fatal(err)
	}
	return rl
}

func TestIPKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"192.0.2.1", "192.0.2.1"},
		{"::ffff:192.0.2.1", "192.0.2.1"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"2001:db8::1", "2001:db8::/64"},
		{"fe80::1%eth0", "fe80::/64"},
	} {
		if got := app.IPKey(netip.MustParseAddr(tc.in)); got != tc.want {
			t.Errorf("IPKey(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := app.IPKey(netip.Addr{}); got != "" {
		t.Errorf("IPKey(zero) = %q, want empty", got)
	}
}

func TestCheckIPSharesSlash64(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rl := newLimits(t, fakes.NewRateLimiter(), 1)
	if err := rl.CheckIP(ctx, app.RuleGlobalIP, netip.MustParseAddr("2001:db8::1")); err != nil {
		t.Fatalf("first hit: %v", err)
	}
	if err := rl.CheckIP(ctx, app.RuleGlobalIP, netip.MustParseAddr("2001:db8::ffff:1")); err == nil {
		t.Error("a second address in the same /64 was allowed: the /64 must share one window")
	}
	if err := rl.CheckIP(ctx, app.RuleGlobalIP, netip.MustParseAddr("2001:db8:0:1::1")); err != nil {
		t.Errorf("an address in another /64 was refused: %v", err)
	}
}

func TestCheckRefuses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rl := newLimits(t, fakes.NewRateLimiter(), 1)
	if err := rl.Check(ctx, app.RuleTokenClient, "reports"); err != nil {
		t.Fatalf("first hit: %v", err)
	}
	err := rl.Check(ctx, app.RuleTokenClient, "reports")
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeRateLimited {
		t.Fatalf("second hit = %v, want RATE_LIMITED", err)
	}
	if de.RetryAfter != time.Minute {
		t.Errorf("RetryAfter = %v, want the decision's %v", de.RetryAfter, time.Minute)
	}
	if err := rl.Check(ctx, app.RuleTokenClient, "billing"); err != nil {
		t.Errorf("another key was refused: %v", err)
	}
	if err := rl.Check(ctx, app.RuleSignInIP, "reports"); err != nil {
		t.Errorf("another rule was refused: %v", err)
	}
}

func TestCheckFailsOpen(t *testing.T) {
	t.Parallel()
	l := fakes.NewRateLimiter()
	l.Fail(errors.New("connection refused"))
	rl := newLimits(t, l, 1)
	for range 3 {
		if err := rl.CheckIP(context.Background(), app.RuleGlobalIP, netip.MustParseAddr("192.0.2.1")); err != nil {
			t.Fatalf("with the limiter failing, CheckIP = %v, want nil (fail open)", err)
		}
	}
}

func TestCheckIPWithoutAddress(t *testing.T) {
	t.Parallel()
	rl := newLimits(t, fakes.NewRateLimiter(), 1)
	for range 3 {
		if err := rl.CheckIP(context.Background(), app.RuleGlobalIP, netip.Addr{}); err != nil {
			t.Fatalf("CheckIP(zero) = %v, want nil", err)
		}
	}
}

func TestNewRateLimitsRefuses(t *testing.T) {
	t.Parallel()
	ok := app.RateLimit{Limit: 1, Window: time.Minute}
	for _, tc := range []struct {
		name string
		edit func(map[app.Rule]app.RateLimit)
	}{
		{"missing rule", func(m map[app.Rule]app.RateLimit) { delete(m, app.RuleResumeIP) }},
		{"zero limit", func(m map[app.Rule]app.RateLimit) { m[app.RuleSendIP] = app.RateLimit{Window: time.Minute} }},
		{"zero window", func(m map[app.Rule]app.RateLimit) { m[app.RuleVerifyIP] = app.RateLimit{Limit: 1} }},
		{"unknown rule", func(m map[app.Rule]app.RateLimit) { m["other"] = ok }},
	} {
		m := rules(ok)
		tc.edit(m)
		if _, err := app.NewRateLimits(fakes.NewRateLimiter(), m); err == nil {
			t.Errorf("%s: NewRateLimits succeeded", tc.name)
		}
	}
}

func TestRules(t *testing.T) {
	t.Parallel()
	want := []app.Rule{"global_ip", "sign_in_ip", "registration_ip", "reset_ip", "send_ip", "verify_ip", "resume_ip", "token_client"}
	got := app.Rules()
	if len(got) != len(want) {
		t.Fatalf("Rules() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Rules()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
