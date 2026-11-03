package caller_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/health"
	"github.com/arafat-hasan/auth1/internal/http/middleware/caller"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/http/server"
	"github.com/arafat-hasan/auth1/internal/testing/apitest"
)

const workload = "spiffe://cluster.local/ns/billing/sa/billing"

// discardAudit accepts every entry.
type discardAudit struct{}

func (discardAudit) Write(_ context.Context, e app.AuditEntry) error { return e.Check() }

// api is the stub API with the caller middleware, as serve mounts it.
func api(t *testing.T, scopes ...string) http.Handler {
	t.Helper()
	return apiAt(t, "", slog.New(slog.DiscardHandler), scopes...)
}

// apiAt is api under basePath, logging to logger.
func apiAt(t *testing.T, basePath string, logger *slog.Logger, scopes ...string) http.Handler {
	t.Helper()
	meter := noop.NewMeterProvider().Meter("test")
	hist, err := meter.Float64Histogram("d")
	if err != nil {
		t.Fatal(err)
	}
	denied, err := meter.Int64Counter("auth1_service_calls_denied_total")
	if err != nil {
		t.Fatal(err)
	}
	pw := problem.New(logger)
	res, err := caller.New(caller.Options{
		Mode: caller.ModeMesh, Source: caller.SourceHeader, Header: "X-Forwarded-Client-Cert", BasePath: basePath,
		Format: caller.FormatXFCC, TrustedSidecars: []string{"127.0.0.1/32", "::1/128"},
		Callers:  map[string][]string{workload: scopes},
		Problems: pw, Audit: discardAudit{}, Denied: denied, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server.NewRouter(server.Options{
		BasePath: basePath, Logger: logger, Problems: pw,
		TracerProvider: tracenoop.NewTracerProvider(), Propagator: propagation.TraceContext{},
		RequestDuration: hist, Health: health.New(logger),
		Routes: gen.Routes(gen.Stub{}, pw), APIMiddleware: []func(http.Handler) http.Handler{res.Middleware},
	})
}

// introspect is POST /v1/introspect from remote with the workload's XFCC header.
func introspect(remote string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/introspect", strings.NewReader("token=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Client-Cert", `Hash=abc;Subject="CN=billing";URI=`+workload)
	req.RemoteAddr = remote
	return req
}

func problemCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var b struct{ Code string }
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return b.Code
}

// TestT10: a caller without the scope gets CALLER_NOT_ALLOWED, and an identity header from a
// non-sidecar address is ignored (SDD T-10). Both answers are checked against the contract.
func TestT10(t *testing.T) {
	t.Parallel()
	v := apitest.New(t)

	resp := v.Serve(t, api(t, "directory:read"), introspect("127.0.0.1:41000"))
	if resp.StatusCode != http.StatusForbidden || problemCode(t, resp) != "CALLER_NOT_ALLOWED" {
		t.Errorf("without tokens:introspect: status %d, want 403 CALLER_NOT_ALLOWED", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = v.Serve(t, api(t, "tokens:introspect"), introspect("203.0.113.9:41000"))
	if resp.StatusCode != http.StatusUnauthorized || problemCode(t, resp) != "TOKEN_INVALID" {
		t.Errorf("identity header from a non-sidecar address: status %d, want 401 TOKEN_INVALID", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// With the scope from the sidecar the call passes the check and reaches the stub, whose 501 is
	// not in the contract, so it is not validated.
	w := httptest.NewRecorder()
	api(t, "tokens:introspect").ServeHTTP(w, introspect("127.0.0.1:41000"))
	if w.Code != http.StatusNotImplemented {
		t.Errorf("with the scope from the sidecar: status %d, want the stub's 501\n%s", w.Code, w.Body)
	}
}

// TestEveryServiceOperationRequiresCaller: under a base path, every service operation of the
// contract refuses a request with no caller, whatever the escaping of its path parameter, so no
// route reaches its handler past the middleware.
func TestEveryServiceOperationRequiresCaller(t *testing.T) {
	t.Parallel()
	h := apiAt(t, "/auth", slog.New(slog.DiscardHandler), "tokens:introspect")
	n := 0
	for id, op := range gen.Operations {
		if !op.IsService() {
			continue
		}
		n++
		for _, seg := range []string{"0190a0a0-0000-7000-8000-000000000001", "a%2Fb", "a%252Fb", "%2E%2E"} {
			path := "/auth" + strings.ReplaceAll(op.Path, "{accountId}", seg)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(op.Method, path, strings.NewReader("{}")))
			if w.Code != http.StatusUnauthorized && w.Code != http.StatusNotFound {
				t.Errorf("%s: %s %s = %d, want 401 (or 404 for no route)", id, op.Method, path, w.Code)
			}
			if seg == "0190a0a0-0000-7000-8000-000000000001" && w.Code != http.StatusUnauthorized {
				t.Errorf("%s: %s %s = %d, want 401", id, op.Method, path, w.Code)
			}
		}
	}
	if n < 12 {
		t.Errorf("%d service operations, want the contract's 12", n)
	}
}

// TestDenialLogRouteHasBasePath: the denial's log line carries the route pattern under the base
// path, not the request path.
func TestDenialLogRouteHasBasePath(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	h := apiAt(t, "/auth", slog.New(slog.NewJSONHandler(&logs, nil)), "directory:read")
	req := httptest.NewRequest(http.MethodDelete, "/auth/v1/accounts/0190a0a0-0000-7000-8000-000000000001", nil)
	req.Header.Set("X-Forwarded-Client-Cert", "URI="+workload)
	req.RemoteAddr = "127.0.0.1:41000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", w.Code)
	}
	if !strings.Contains(logs.String(), `"route":"/auth/v1/accounts/{accountId}"`) || strings.Contains(logs.String(), "0190a0a0") {
		t.Errorf("denial log route:\n%s", &logs)
	}
}
