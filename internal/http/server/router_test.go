package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/http/health"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/http/requestid"
)

// testOptions returns router options with no-op telemetry and the test routes.
func testOptions(t *testing.T, basePath string) Options {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	hist, err := noop.NewMeterProvider().Meter("test").Float64Histogram("d")
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		BasePath:        basePath,
		Logger:          logger,
		Problems:        problem.New(logger),
		TracerProvider:  tracenoop.NewTracerProvider(),
		Propagator:      propagation.TraceContext{},
		RequestDuration: hist,
		Health:          health.New(logger),
		Routes: func(r chi.Router) {
			r.Get("/v1/ping", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("pong")) })
			r.Get("/v1/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
		},
	}
}

func TestNewServerTimeouts(t *testing.T) {
	t.Parallel()

	// TDD-07 §7.
	want := map[string]time.Duration{"read header": 5 * time.Second, "read": 10 * time.Second,
		"write": 15 * time.Second, "idle": 60 * time.Second}
	srv := NewServer(http.NotFoundHandler(), nil)
	got := map[string]time.Duration{"read header": srv.ReadHeaderTimeout, "read": srv.ReadTimeout,
		"write": srv.WriteTimeout, "idle": srv.IdleTimeout}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s timeout %v, want %v", k, got[k], v)
		}
	}
	if MaxBodyBytes != 64<<10 {
		t.Errorf("MaxBodyBytes %d, want 65536", MaxBodyBytes)
	}
}

func TestRouter(t *testing.T) {
	t.Parallel()

	type probe struct {
		method, path string
		want         int
	}
	tests := []struct {
		basePath string
		probes   []probe
	}{
		{basePath: "", probes: []probe{
			{"GET", "/livez", 200}, {"GET", "/readyz", 200}, {"GET", "/v1/ping", 200},
			{"HEAD", "/livez", 200}, {"HEAD", "/readyz", 200}, {"HEAD", "/nope", 404},
			{"GET", "/auth/v1/ping", 404}, {"GET", "/nope", 404}, {"POST", "/livez", 404},
			{"POST", "/v1/ping", 404}, {"FOO", "/v1/ping", 404},
		}},
		{basePath: "/auth", probes: []probe{
			{"GET", "/livez", 200}, {"GET", "/readyz", 200}, {"GET", "/auth/v1/ping", 200},
			{"HEAD", "/livez", 200}, {"HEAD", "/auth/livez", 404},
			{"GET", "/v1/ping", 404}, {"GET", "/auth/livez", 404}, {"GET", "/auth/nope", 404},
			{"POST", "/auth/v1/ping", 404}, {"GET", "/nope", 404},
		}},
	}
	for _, tt := range tests {
		h := NewRouter(testOptions(t, tt.basePath))
		for _, p := range tt.probes {
			t.Run(tt.basePath+" "+p.method+" "+p.path, func(t *testing.T) {
				t.Parallel()
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(p.method, p.path, nil))
				if rec.Code != p.want {
					t.Errorf("status %d, want %d", rec.Code, p.want)
				}
				if rec.Header().Get(requestid.Header) == "" {
					t.Error("no request id")
				}
				if p.want == 404 {
					var body map[string]any
					if ct := rec.Header().Get("Content-Type"); ct != problem.ContentType {
						t.Errorf("Content-Type %q", ct)
					}
					if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["code"] != "NOT_FOUND" {
						t.Errorf("body %s", rec.Body)
					}
				}
			})
		}
	}
}

func TestRouterBodyLimit(t *testing.T) {
	t.Parallel()

	opts := testOptions(t, "")
	opts.Routes = func(r chi.Router) {
		r.Post("/v1/echo", func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.ReadAll(r.Body); err != nil {
				opts.Problems.Write(w, r, err)
			}
		})
	}
	h := NewRouter(opts)
	req := httptest.NewRequest(http.MethodPost, "/v1/echo", http.NoBody)
	req.ContentLength = MaxBodyBytes + 1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", rec.Code)
	}
}

func TestPanicKeepsServing(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(NewRouter(testOptions(t, "")))
	defer srv.Close()

	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path) //nolint:noctx // test server
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("/v1/panic"); code != http.StatusServiceUnavailable {
		t.Errorf("panic: status %d body %s", code, body)
	}
	if code, body := get("/v1/ping"); code != http.StatusOK || body != "pong" {
		t.Errorf("after the panic: status %d body %q", code, body)
	}
}
