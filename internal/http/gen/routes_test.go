package gen_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/health"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/http/server"
)

// router returns the API router with gen.Routes(gen.Stub{}) mounted under basePath, and
// the buffer its JSON logs go to.
func router(t *testing.T, basePath string) (http.Handler, *bytes.Buffer) {
	t.Helper()
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	hist, err := noop.NewMeterProvider().Meter("test").Float64Histogram("d")
	if err != nil {
		t.Fatal(err)
	}
	pw := problem.New(logger)
	return server.NewRouter(server.Options{
		BasePath:        basePath,
		Logger:          logger,
		Problems:        pw,
		TracerProvider:  tracenoop.NewTracerProvider(),
		Propagator:      propagation.TraceContext{},
		RequestDuration: hist,
		Health:          health.New(logger),
		Routes:          gen.Routes(gen.Stub{}, pw),
	}), logs
}

// loggedRoute returns the route attribute of the access log line.
func loggedRoute(t *testing.T, logs *bytes.Buffer) string {
	t.Helper()
	sc := bufio.NewScanner(logs)
	for sc.Scan() {
		var line map[string]any
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("log line is not JSON: %v: %s", err, sc.Bytes())
		}
		if route, ok := line["route"].(string); ok {
			return route
		}
	}
	t.Fatalf("no access log line with a route in:\n%s", logs)
	return ""
}

var pathParam = regexp.MustCompile(`\{[^}]+\}`)

// TestRoutesNotImplemented sends every operation of the contract to the stub, and checks the 501
// problem and that the route is logged as the Chi pattern, not the path.
func TestRoutesNotImplemented(t *testing.T) {
	t.Parallel()

	if len(gen.Operations) == 0 {
		t.Fatal("gen.Operations is empty")
	}
	for _, basePath := range []string{"", "/auth"} {
		for id, op := range gen.Operations {
			t.Run(basePath+"/"+id, func(t *testing.T) {
				t.Parallel()
				h, logs := router(t, basePath)
				path := basePath + pathParam.ReplaceAllString(op.Path, "0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b")
				req := httptest.NewRequest(op.Method, path, strings.NewReader("{}"))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Idempotency-Key", "k")
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)

				if rec.Code != http.StatusNotImplemented {
					t.Errorf("%s %s: status %d, want 501: %s", op.Method, path, rec.Code, rec.Body)
				}
				if got := rec.Header().Get("Content-Type"); got != problem.ContentType {
					t.Errorf("Content-Type %q, want %q", got, problem.ContentType)
				}
				if got, want := loggedRoute(t, logs), basePath+op.Path; got != want {
					t.Errorf("logged route %q, want %q", got, want)
				}
			})
		}
	}
}

// TestRoutesBindError checks that a request the generated code cannot bind answers a
// VALIDATION_FAILED problem, not the generator's plain-text 400, and that a body found to be over
// the limit only while it is decoded (no Content-Length) still answers 413.
func TestRoutesBindError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, method, path, body string
		chunked                  bool // send no Content-Length, so the limit is found while decoding
		want                     int
	}{
		{name: "path parameter", method: http.MethodDelete, path: "/v1/me/sessions/not-a-uuid", want: http.StatusUnprocessableEntity},
		{name: "header parameter", method: http.MethodPost, // no Idempotency-Key
			path: "/v1/accounts/0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b/sessions/revoke", want: http.StatusUnprocessableEntity},
		{name: "JSON body", method: http.MethodPost, path: "/v1/sessions", body: "{", want: http.StatusUnprocessableEntity},
		{name: "chunked body over the limit", method: http.MethodPost, path: "/v1/sessions", chunked: true,
			body: `{"client_id":"` + strings.Repeat("a", server.MaxBodyBytes) + `"}`, want: http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h, _ := router(t, "")
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.chunked {
				req.ContentLength = -1
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Errorf("status %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
			var body struct{ Code string }
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not JSON: %v: %s", err, rec.Body)
			}
			if body.Code != "VALIDATION_FAILED" {
				t.Errorf("code %q, want VALIDATION_FAILED", body.Code)
			}
		})
	}
}
