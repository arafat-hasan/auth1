package middleware

import (
	"net/http"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/http/clientip"
	"github.com/arafat-hasan/auth1/internal/http/problem"
)

// RateLimit applies L-1, the global per-IP limit (TDD-07 §2), to every request that exempt does
// not exempt (nil exempts none), keyed by the client IP that clientip's middleware kept. A request
// over the limit gets 429 RATE_LIMITED with Retry-After through pw and goes no further; when the
// limiter fails, requests pass (TDD-07 §8).
func RateLimit(limits *app.RateLimits, pw *problem.Writer, exempt func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if exempt == nil || !exempt(r) {
				if err := limits.CheckIP(r.Context(), app.RuleGlobalIP, clientip.From(r.Context())); err != nil {
					pw.Write(w, r, err)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
