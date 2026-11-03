package caller_test

import (
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
	logger := slog.New(slog.DiscardHandler)
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
		Mode: caller.ModeMesh, Source: caller.SourceHeader, Header: "X-Forwarded-Client-Cert",
		Format: caller.FormatXFCC, TrustedSidecars: []string{"127.0.0.1/32", "::1/128"},
		Callers:  map[string][]string{workload: scopes},
		Problems: pw, Audit: discardAudit{}, Denied: denied, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server.NewRouter(server.Options{
		Logger: logger, Problems: pw,
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
