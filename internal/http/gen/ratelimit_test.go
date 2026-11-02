package gen_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/health"
	"github.com/arafat-hasan/auth1/internal/http/middleware"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/http/server"
	"github.com/arafat-hasan/auth1/internal/testing/apitest"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// limitedRouter is the stub API under basePath with apiMiddleware on its routes.
func limitedRouter(t *testing.T, basePath string, apiMiddleware ...func(http.Handler) http.Handler) http.Handler {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	hist, err := noop.NewMeterProvider().Meter("test").Float64Histogram("d")
	if err != nil {
		t.Fatal(err)
	}
	pw := problem.New(logger)
	return server.NewRouter(server.Options{
		BasePath: basePath, Logger: logger, Problems: pw,
		TracerProvider: tracenoop.NewTracerProvider(), Propagator: propagation.TraceContext{},
		RequestDuration: hist, Health: health.New(logger),
		Routes: gen.Routes(gen.Stub{}, pw), APIMiddleware: apiMiddleware,
	})
}

func TestServiceRoute(t *testing.T) {
	t.Parallel()
	for _, basePath := range []string{"", "/auth"} {
		var got bool
		record := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = gen.ServiceRoute(basePath)(r)
				next.ServeHTTP(w, r)
			})
		}
		h := limitedRouter(t, basePath, record)
		for _, tc := range []struct {
			method, path string
			want         bool
		}{
			{http.MethodPost, "/v1/introspect", true},
			{http.MethodPut, "/v1/accounts/0190a0a0-0000-7000-8000-000000000001/roles", true},
			{http.MethodPost, "/v1/hooks/delivery/resolve", true},
			{http.MethodGet, "/.well-known/jwks.json", false},
			{http.MethodPost, "/v1/sessions", false},
			{http.MethodGet, "/v1/me", false},
			{http.MethodGet, "/v1/introspect", false},
			{http.MethodGet, "/v1/nope", false},
		} {
			got = false
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, basePath+tc.path, nil))
			if got != tc.want {
				t.Errorf("base %q: ServiceRoute(%s %s) = %v, want %v", basePath, tc.method, tc.path, got, tc.want)
			}
		}
	}
}

// TestRateLimitedJWKS: a request over L-1 answers the contract's 429, with Retry-After, and a
// service operation is never limited.
func TestRateLimitedJWKS(t *testing.T) {
	t.Parallel()
	rules := map[app.Rule]app.RateLimit{}
	for _, r := range app.Rules() {
		rules[r] = app.RateLimit{Limit: 1, Window: time.Minute}
	}
	limits, err := app.NewRateLimits(fakes.NewRateLimiter(), rules)
	if err != nil {
		t.Fatal(err)
	}
	pw := problem.New(slog.New(slog.DiscardHandler))
	h := limitedRouter(t, "", middleware.RateLimit(limits, pw, gen.ServiceRoute("")))
	v := apitest.New(t)
	// The stub answers the first request 501, outside the contract, so only the second is checked.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	resp := v.Serve(t, h, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "60" {
		t.Fatalf("second request: %d, Retry-After %q; want 429 and 60", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	for range 3 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/introspect", nil))
		if rec.Code == http.StatusTooManyRequests {
			t.Fatal("a service operation was rate limited")
		}
	}
}
