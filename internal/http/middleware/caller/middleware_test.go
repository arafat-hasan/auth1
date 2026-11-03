package caller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/go-cmp/cmp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/http/clientip"
	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/telemetry"
)

const (
	actor     = "staff:7f3c0d4e"
	sidecar   = "127.0.0.1:41000"
	elsewhere = "10.1.2.3:41000"
)

// audit records the entries written, or fails every write with err.
type audit struct {
	mu      sync.Mutex
	entries []app.AuditEntry
	err     error
}

func (a *audit) Write(_ context.Context, e app.AuditEntry) error {
	if err := e.Check(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.entries = append(a.entries, e)
	return nil
}

func (a *audit) written() []app.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.entries)
}

// tokens is a TokenVerifier accepting the token "good" for the client "reports".
type tokens struct{}

func (tokens) VerifyServiceToken(_ context.Context, token string) (Caller, error) {
	if token != "good" {
		return Caller{}, errors.New("bad token")
	}
	return Caller{Kind: KindClient, ID: "reports", Scopes: []string{"tokens:introspect"}}, nil
}

// rig is a Chi router with a Resolver on its API routes; each handler records the Caller.
type rig struct {
	h      http.Handler
	audit  *audit
	reader *sdkmetric.ManualReader
	logs   *bytes.Buffer

	mu      sync.Mutex
	reached bool
	caller  Caller
	found   bool
}

// newRig builds the rig; edit adjusts the options before New.
func newRig(t *testing.T, edit func(*Options)) *rig {
	t.Helper()
	rg := &rig{audit: &audit{}, reader: sdkmetric.NewManualReader(), logs: &bytes.Buffer{}}
	logger := slog.New(slog.NewJSONHandler(rg.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	denied, err := telemetry.NewMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(rg.reader))).
		Counter("auth1_service_calls_denied_total")
	if err != nil {
		t.Fatal(err)
	}
	o := Options{
		Mode:            ModeMesh,
		Source:          SourceHeader,
		Header:          "X-Forwarded-Client-Cert",
		Format:          FormatXFCC,
		TrustedSidecars: sidecars,
		Callers: map[string][]string{
			spiffe:                     {"tokens:introspect", "directory:read"},
			"spiffe://example/sa/none": nil,
		},
		Problems: problem.New(logger),
		Audit:    rg.audit,
		Denied:   denied,
		Logger:   logger,
	}
	if edit != nil {
		edit(&o)
	}
	res := mustNew(t, o)
	ips, _ := clientip.New(nil)
	r := chi.NewRouter()
	r.Use(ips.Middleware, res.Middleware)
	record := func(w http.ResponseWriter, req *http.Request) {
		rg.mu.Lock()
		rg.reached = true
		rg.caller, rg.found = From(req.Context())
		rg.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}
	for _, op := range gen.Operations {
		r.Method(op.Method, op.Path, http.HandlerFunc(record))
	}
	rg.h = r
	return rg
}

// call sends method path from remote with headers ("Name: value" each) and returns the response.
func (rg *rig) call(t *testing.T, method, path, remote string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	rg.mu.Lock()
	rg.reached, rg.caller, rg.found = false, Caller{}, false
	rg.mu.Unlock()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	for _, h := range headers {
		k, v, _ := strings.Cut(h, ": ")
		req.Header.Add(k, v)
	}
	w := httptest.NewRecorder()
	rg.h.ServeHTTP(w, req)
	return w
}

// code returns the problem code of resp, failing t unless its status is want.
func code(t *testing.T, resp *httptest.ResponseRecorder, want int) string {
	t.Helper()
	if resp.Code != want {
		t.Fatalf("status %d, want %d", resp.Code, want)
	}
	var b struct{ Code string }
	_ = json.NewDecoder(resp.Body).Decode(&b)
	return b.Code
}

// denials returns auth1_service_calls_denied_total by "caller scope".
func (rg *rig) denials(t *testing.T) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := rg.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "auth1_service_calls_denied_total" {
				continue
			}
			for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
				c, _ := dp.Attributes.Value("caller")
				s, _ := dp.Attributes.Value("scope")
				got[c.AsString()+" "+s.AsString()] += dp.Value
			}
		}
	}
	return got
}

func xfcc(id string) string { return "X-Forwarded-Client-Cert: URI=" + id }

func TestNonServiceRoutePassesThrough(t *testing.T) {
	t.Parallel()
	rg := newRig(t, nil)
	resp := rg.call(t, http.MethodGet, "/v1/me", sidecar, xfcc(spiffe), "Auth1-Actor: \x01")
	if resp.Code != http.StatusNoContent || !rg.reached {
		t.Fatalf("GET /v1/me: status %d, reached %v; want the handler", resp.Code, rg.reached)
	}
	if rg.found {
		t.Errorf("GET /v1/me has a Caller %+v", rg.caller)
	}
	if n := len(rg.audit.written()); n != 0 {
		t.Errorf("%d audit entries", n)
	}
}

func TestNoCallerUnauthorized(t *testing.T) {
	t.Parallel()
	rg := newRig(t, nil)
	for _, tc := range []struct {
		name    string
		remote  string
		headers []string
	}{
		{"no identity", sidecar, nil},
		{"identity from a non-sidecar address", elsewhere, []string{xfcc(spiffe)}},
		{"two XFCC elements", sidecar, []string{"X-Forwarded-Client-Cert: URI=" + spiffe + ",URI=spiffe://b"}},
	} {
		resp := rg.call(t, http.MethodPost, "/v1/introspect", tc.remote, tc.headers...)
		if got := code(t, resp, http.StatusUnauthorized); got != "TOKEN_INVALID" || rg.reached {
			t.Errorf("%s: code %q, reached %v; want TOKEN_INVALID, not reached", tc.name, got, rg.reached)
		}
	}
	if n := len(rg.audit.written()); n != 0 {
		t.Errorf("%d audit entries for unauthenticated requests", n)
	}
	if d := rg.denials(t); len(d) != 0 {
		t.Errorf("denials %v for unauthenticated requests", d)
	}
}

// TestScopeEnforced: a caller without the operation's x-auth1-scope never reaches the handler.
func TestScopeEnforced(t *testing.T) {
	t.Parallel()
	rg := newRig(t, nil)
	resp := rg.call(t, http.MethodPut, "/v1/accounts/0190a0a0-0000-7000-8000-000000000001/roles", sidecar, xfcc(spiffe))
	if got := code(t, resp, http.StatusForbidden); got != "CALLER_NOT_ALLOWED" || rg.reached {
		t.Fatalf("without accounts:roles:write: code %q, reached %v", got, rg.reached)
	}
	resp = rg.call(t, http.MethodPost, "/v1/introspect", sidecar, xfcc(spiffe))
	if resp.Code != http.StatusNoContent || !rg.reached || !rg.found {
		t.Fatalf("with tokens:introspect: status %d, reached %v, caller %v", resp.Code, rg.reached, rg.found)
	}
	want := Caller{Kind: KindWorkload, ID: spiffe, Scopes: []string{"tokens:introspect", "directory:read"}}
	if diff := cmp.Diff(want, rg.caller); diff != "" {
		t.Errorf("Caller (-want +got):\n%s", diff)
	}
}

func TestUnknownIdentityDenied(t *testing.T) {
	t.Parallel()
	rg := newRig(t, nil)
	resp := rg.call(t, http.MethodPost, "/v1/introspect", sidecar, xfcc("spiffe://cluster.local/ns/evil/sa/evil"))
	if got := code(t, resp, http.StatusForbidden); got != "CALLER_NOT_ALLOWED" {
		t.Fatalf("code %q", got)
	}
	if diff := cmp.Diff(map[string]int64{"unknown tokens:introspect": 1}, rg.denials(t)); diff != "" {
		t.Errorf("denials (-want +got):\n%s", diff)
	}
}

// TestIdentityComparedExactly: an identity that only resembles a configured one has no scopes.
func TestIdentityComparedExactly(t *testing.T) {
	t.Parallel()
	rg := newRig(t, nil)
	for _, id := range []string{spiffe + "/", strings.ToUpper(spiffe), " " + spiffe, "spiffe://cluster.local/ns/billing/sa/billing2"} {
		resp := rg.call(t, http.MethodPost, "/v1/introspect", sidecar, "X-Forwarded-Client-Cert: URI=\""+id+"\"")
		if got := code(t, resp, http.StatusForbidden); got != "CALLER_NOT_ALLOWED" {
			t.Errorf("identity %q: code %q, want CALLER_NOT_ALLOWED", id, got)
		}
	}
}

// TestModeSelectsCredential: each mode accepts only its own credential; both accepts either.
func TestModeSelectsCredential(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode             Mode
		workload, bearer int // the status with the workload identity, with the token
	}{
		{ModeNone, http.StatusUnauthorized, http.StatusUnauthorized},
		{ModeMesh, http.StatusNoContent, http.StatusUnauthorized},
		{ModeClientCredentials, http.StatusUnauthorized, http.StatusNoContent},
		{ModeBoth, http.StatusNoContent, http.StatusNoContent},
	} {
		rg := newRig(t, func(o *Options) { o.Mode = tc.mode; o.Tokens = tokens{} })
		if got := rg.call(t, http.MethodPost, "/v1/introspect", sidecar, xfcc(spiffe)).Code; got != tc.workload {
			t.Errorf("mode %v, workload identity: status %d, want %d", tc.mode, got, tc.workload)
		}
		resp := rg.call(t, http.MethodPost, "/v1/introspect", elsewhere, "Authorization: Bearer good")
		if resp.Code != tc.bearer {
			t.Errorf("mode %v, service token: status %d, want %d", tc.mode, resp.Code, tc.bearer)
		}
		if resp.Code == http.StatusNoContent && (rg.caller.Kind != KindClient || rg.caller.ID != "reports") {
			t.Errorf("mode %v, service token: Caller %+v", tc.mode, rg.caller)
		}
		if got := rg.call(t, http.MethodPost, "/v1/introspect", elsewhere, "Authorization: Bearer bad").Code; got != http.StatusUnauthorized {
			t.Errorf("mode %v, bad token: status %d, want 401", tc.mode, got)
		}
	}
}

// TestServiceTokenOnlyWithoutHookDenied: until WP-70 fills the hook, an operation whose only
// scheme is serviceToken accepts no caller, not even a workload identity.
func TestServiceTokenOnlyWithoutHookDenied(t *testing.T) {
	t.Parallel()
	tokenOnly := func(*http.Request) (string, gen.Operation, bool) {
		return "tokenOnly", gen.Operation{Method: http.MethodPost, Path: "/v1/introspect", Scope: "tokens:introspect", Security: []string{"serviceToken"}}, true
	}
	rg := newRig(t, func(o *Options) { o.Mode = ModeBoth; o.Match = tokenOnly })
	for _, h := range []string{xfcc(spiffe), "Authorization: Bearer good"} {
		if got := code(t, rg.call(t, http.MethodPost, "/v1/introspect", sidecar, h), http.StatusUnauthorized); got != "TOKEN_INVALID" {
			t.Errorf("no hook, %q: code %q", h, got)
		}
	}
	rg = newRig(t, func(o *Options) { o.Mode = ModeBoth; o.Match = tokenOnly; o.Tokens = tokens{} })
	if got := rg.call(t, http.MethodPost, "/v1/introspect", sidecar, xfcc(spiffe)).Code; got != http.StatusUnauthorized {
		t.Errorf("hook, workload identity on a serviceToken-only operation: status %d, want 401", got)
	}
	if got := rg.call(t, http.MethodPost, "/v1/introspect", sidecar, "Authorization: Bearer good").Code; got != http.StatusNoContent {
		t.Errorf("hook, good token: status %d, want 204", got)
	}
}

func TestDenialAuditedAndCounted(t *testing.T) {
	t.Parallel()
	rg := newRig(t, nil)
	resp := rg.call(t, http.MethodDelete, "/v1/accounts/0190a0a0-0000-7000-8000-000000000001", sidecar,
		xfcc(spiffe), "Auth1-Actor: "+actor, "User-Agent: billing/1.2")
	if got := code(t, resp, http.StatusForbidden); got != "CALLER_NOT_ALLOWED" {
		t.Fatalf("code %q", got)
	}
	want := []app.AuditEntry{{
		ActorKind: app.ActorService, ActorID: spiffe, OnBehalf: actor,
		Action: ActionDenied, Outcome: app.OutcomeFailure,
		IP: netip.MustParseAddr("127.0.0.1"), UserAgent: "billing/1.2",
		Details: map[string]any{"operation": "deleteAccount", "scope": "accounts:delete"},
	}}
	if diff := cmp.Diff(want, rg.audit.written(), cmp.Comparer(func(a, b netip.Addr) bool { return a == b })); diff != "" {
		t.Errorf("audit (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(map[string]int64{spiffe + " accounts:delete": 1}, rg.denials(t)); diff != "" {
		t.Errorf("denials (-want +got):\n%s", diff)
	}
}

// TestAuditFailureStillDenies: a failed audit write is logged and the request is still refused.
func TestAuditFailureStillDenies(t *testing.T) {
	t.Parallel()
	rg := newRig(t, nil)
	rg.audit.err = errors.New("database down")
	resp := rg.call(t, http.MethodDelete, "/v1/accounts/0190a0a0-0000-7000-8000-000000000001", sidecar, xfcc(spiffe))
	if got := code(t, resp, http.StatusForbidden); got != "CALLER_NOT_ALLOWED" || rg.reached {
		t.Fatalf("code %q, reached %v", got, rg.reached)
	}
	if !strings.Contains(rg.logs.String(), `"level":"ERROR"`) || !strings.Contains(rg.logs.String(), "database down") {
		t.Errorf("audit failure not logged at error level:\n%s", rg.logs)
	}
}

func TestActorValidation(t *testing.T) {
	t.Parallel()
	rg := newRig(t, nil)
	for _, tc := range []struct {
		name    string
		headers []string
	}{
		{"empty", []string{"Auth1-Actor: "}},
		{"129 characters", []string{"Auth1-Actor: " + strings.Repeat("a", 129)}},
		{"control character", []string{"Auth1-Actor: staff:\x7f"}},
		{"non-ASCII", []string{"Auth1-Actor: staff:é"}},
		{"two values", []string{"Auth1-Actor: staff:a", "Auth1-Actor: staff:b"}},
	} {
		resp := rg.call(t, http.MethodPost, "/v1/directory/accounts/batch-get", sidecar, append(tc.headers, xfcc(spiffe))...)
		if got := code(t, resp, http.StatusUnprocessableEntity); got != "VALIDATION_FAILED" || rg.reached {
			t.Errorf("%s: code %q, reached %v; want VALIDATION_FAILED", tc.name, got, rg.reached)
		}
	}
	long := strings.Repeat("~", 128)
	for _, a := range []string{actor, long, " x "} {
		resp := rg.call(t, http.MethodPost, "/v1/directory/accounts/batch-get", sidecar, xfcc(spiffe), "Auth1-Actor: "+a)
		if resp.Code != http.StatusNoContent || rg.caller.Actor != a {
			t.Errorf("actor %q: status %d, Caller.Actor %q", a, resp.Code, rg.caller.Actor)
		}
	}
	// A malformed actor from a caller without the scope is still CALLER_NOT_ALLOWED, and the audit
	// row has no on_behalf.
	resp := rg.call(t, http.MethodDelete, "/v1/accounts/0190a0a0-0000-7000-8000-000000000001", sidecar, xfcc(spiffe), "Auth1-Actor: \x01")
	if got := code(t, resp, http.StatusForbidden); got != "CALLER_NOT_ALLOWED" {
		t.Errorf("malformed actor without the scope: code %q", got)
	}
	if e := rg.audit.written(); len(e) != 1 || e[0].OnBehalf != "" {
		t.Errorf("audit %+v, want one entry without on_behalf", e)
	}
}

// TestDenialLogsNoSecrets: the denial's log line has the route pattern and the decision, never
// the identity header, the identity or the actor (G-6).
func TestDenialLogsNoSecrets(t *testing.T) {
	t.Parallel()
	rg := newRig(t, func(o *Options) { o.BasePath = "" })
	rg.call(t, http.MethodDelete, "/v1/accounts/0190a0a0-0000-7000-8000-000000000001", sidecar, xfcc(spiffe), "Auth1-Actor: "+actor)
	rg.audit.err = errors.New("database down")
	rg.call(t, http.MethodDelete, "/v1/accounts/0190a0a0-0000-7000-8000-000000000001", sidecar, xfcc(spiffe), "Auth1-Actor: "+actor)
	logs := rg.logs.String()
	if !strings.Contains(logs, `"route":"/v1/accounts/{accountId}"`) || !strings.Contains(logs, `"decision":"denied"`) {
		t.Errorf("no route pattern or decision in:\n%s", logs)
	}
	for _, secret := range []string{spiffe, actor, "URI=", "0190a0a0"} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain %q:\n%s", secret, logs)
		}
	}
}

// TestModeBothFallsBackToToken: in mode both, a workload identity that service_auth.callers does
// not name does not shadow a valid service token (TDD-05 §3: either is accepted); a configured
// workload identity still wins, and with no valid token the unknown identity is denied as before.
func TestModeBothFallsBackToToken(t *testing.T) {
	t.Parallel()
	rg := newRig(t, func(o *Options) { o.Mode = ModeBoth; o.Tokens = tokens{} })
	unknown := xfcc("spiffe://cluster.local/ns/reports/sa/reports")

	if got := rg.call(t, http.MethodPost, "/v1/introspect", sidecar, unknown, "Authorization: Bearer good").Code; got != http.StatusNoContent {
		t.Fatalf("unconfigured identity and a valid token: status %d, want 204", got)
	}
	if rg.caller.Kind != KindClient || rg.caller.ID != "reports" {
		t.Errorf("unconfigured identity and a valid token: Caller %+v, want the client", rg.caller)
	}
	if n := len(rg.audit.written()); n != 0 {
		t.Errorf("%d audit entries for an accepted call", n)
	}

	if got := rg.call(t, http.MethodPost, "/v1/introspect", sidecar, xfcc(spiffe), "Authorization: Bearer good").Code; got != http.StatusNoContent {
		t.Fatalf("configured identity and a valid token: status %d, want 204", got)
	}
	if rg.caller.Kind != KindWorkload || rg.caller.ID != spiffe {
		t.Errorf("configured identity and a valid token: Caller %+v, want the workload", rg.caller)
	}

	resp := rg.call(t, http.MethodPost, "/v1/introspect", sidecar, unknown, "Authorization: Bearer bad")
	if got := code(t, resp, http.StatusForbidden); got != "CALLER_NOT_ALLOWED" {
		t.Errorf("unconfigured identity and a bad token: code %q, want CALLER_NOT_ALLOWED", got)
	}
}

// verifier is a TokenVerifier returning c for the token "good", counting its calls.
type verifier struct {
	c     Caller
	calls atomic.Int32
}

func (v *verifier) VerifyServiceToken(_ context.Context, token string) (Caller, error) {
	v.calls.Add(1)
	if token != "good" {
		return Caller{}, errors.New("bad token")
	}
	return v.c, nil
}

// TestVerifierResultChecked: a verifier's caller counts only as a client with an id, and only its
// kind, id and scopes are kept.
func TestVerifierResultChecked(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		c    Caller
		want int
	}{
		{"workload kind", Caller{Kind: KindWorkload, ID: "reports", Scopes: []string{"tokens:introspect"}}, http.StatusUnauthorized},
		{"no kind", Caller{ID: "reports", Scopes: []string{"tokens:introspect"}}, http.StatusUnauthorized},
		{"no id", Caller{Kind: KindClient, Scopes: []string{"tokens:introspect"}}, http.StatusUnauthorized},
		{"client", Caller{Kind: KindClient, ID: "reports", Scopes: []string{"tokens:introspect"}, Actor: "forged"}, http.StatusNoContent},
	} {
		rg := newRig(t, func(o *Options) { o.Mode = ModeClientCredentials; o.Tokens = &verifier{c: tc.c} })
		if got := rg.call(t, http.MethodPost, "/v1/introspect", elsewhere, "Authorization: Bearer good").Code; got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
		if tc.want == http.StatusNoContent && rg.caller.Actor != "" {
			t.Errorf("%s: Actor %q from the verifier, want none", tc.name, rg.caller.Actor)
		}
	}
}

// TestBearerParsing: only the Bearer scheme, in any case, with a token, reaches the verifier.
func TestBearerParsing(t *testing.T) {
	t.Parallel()
	v := &verifier{c: Caller{Kind: KindClient, ID: "reports", Scopes: []string{"tokens:introspect"}}}
	rg := newRig(t, func(o *Options) { o.Mode = ModeClientCredentials; o.Tokens = v })
	for _, tc := range []struct {
		header string
		want   int
		calls  int32 // the verifier's calls so far
	}{
		{"Authorization: Basic good", http.StatusUnauthorized, 0},
		{"Authorization: Bearer", http.StatusUnauthorized, 0},
		{"Authorization: Bearer ", http.StatusUnauthorized, 0},
		{"Authorization: good", http.StatusUnauthorized, 0},
		{"Authorization: bearer good", http.StatusNoContent, 1},
		{"Authorization: BEARER good", http.StatusNoContent, 2},
	} {
		if got := rg.call(t, http.MethodPost, "/v1/introspect", elsewhere, tc.header).Code; got != tc.want {
			t.Errorf("%q: status %d, want %d", tc.header, got, tc.want)
		}
		if got := v.calls.Load(); got != tc.calls {
			t.Errorf("%q: verifier called %d times so far, want %d", tc.header, got, tc.calls)
		}
	}
}

// TestClientDenialLabelled: a refused client is counted and audited under its own id, not
// "unknown".
func TestClientDenialLabelled(t *testing.T) {
	t.Parallel()
	rg := newRig(t, func(o *Options) { o.Mode = ModeClientCredentials; o.Tokens = tokens{} })
	resp := rg.call(t, http.MethodDelete, "/v1/accounts/0190a0a0-0000-7000-8000-000000000001", elsewhere, "Authorization: Bearer good")
	if got := code(t, resp, http.StatusForbidden); got != "CALLER_NOT_ALLOWED" {
		t.Fatalf("code %q", got)
	}
	if diff := cmp.Diff(map[string]int64{"reports accounts:delete": 1}, rg.denials(t)); diff != "" {
		t.Errorf("denials (-want +got):\n%s", diff)
	}
	if e := rg.audit.written(); len(e) != 1 || e[0].ActorID != "reports" {
		t.Errorf("audit %+v, want one entry for reports", e)
	}
}
