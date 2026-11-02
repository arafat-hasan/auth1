package middleware_test

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/http/clientip"
	"github.com/arafat-hasan/auth1/internal/http/middleware"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// limited returns a handler behind RateLimit with every rule at limit per 30 s, and a counter of
// the requests that reached it.
func limited(t *testing.T, l app.RateLimiter, limit int, exempt func(*http.Request) bool) (http.Handler, *int) {
	t.Helper()
	rules := map[app.Rule]app.RateLimit{}
	for _, r := range app.Rules() {
		rules[r] = app.RateLimit{Limit: limit, Window: 30 * time.Second}
	}
	limits, err := app.NewRateLimits(l, rules)
	if err != nil {
		t.Fatal(err)
	}
	reached := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached++; w.WriteHeader(http.StatusOK) })
	return middleware.RateLimit(limits, problem.New(slog.New(slog.DiscardHandler)), exempt)(next), &reached
}

func request(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	return r.WithContext(clientip.With(r.Context(), netip.MustParseAddr(ip)))
}

func TestRateLimitRefuses(t *testing.T) {
	t.Parallel()
	h, reached := limited(t, fakes.NewRateLimiter(), 1, nil)
	h.ServeHTTP(httptest.NewRecorder(), request("192.0.2.1"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request("192.0.2.1"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After %q, want 30", got)
	}
	var body struct {
		Code       string `json:"code"`
		RetryAfter int    `json:"retry_after"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != "RATE_LIMITED" || body.RetryAfter != 30 {
		t.Errorf("body %s (%v), want code RATE_LIMITED and retry_after 30", rec.Body, err)
	}
	if *reached != 1 {
		t.Errorf("the handler ran %d times, want 1: a refused request must not reach it", *reached)
	}
	other := httptest.NewRecorder()
	h.ServeHTTP(other, request("192.0.2.2"))
	if other.Code != http.StatusOK {
		t.Errorf("another client got %d, want 200", other.Code)
	}
}

func TestRateLimitFailsOpen(t *testing.T) {
	t.Parallel()
	l := fakes.NewRateLimiter()
	l.Fail(errors.New("connection refused"))
	h, reached := limited(t, l, 1, nil)
	for range 3 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request("192.0.2.1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("with the limiter failing, status %d, want 200", rec.Code)
		}
	}
	if *reached != 3 {
		t.Errorf("the handler ran %d times, want 3", *reached)
	}
}

func TestRateLimitExempt(t *testing.T) {
	t.Parallel()
	l := fakes.NewRateLimiter()
	h, _ := limited(t, l, 1, func(*http.Request) bool { return true })
	for range 3 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request("192.0.2.1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("exempt request got %d, want 200", rec.Code)
		}
	}
	if n := l.Hits(app.RuleGlobalIP, "192.0.2.1"); n != 0 {
		t.Errorf("exempt requests counted %d hits, want 0", n)
	}
}
