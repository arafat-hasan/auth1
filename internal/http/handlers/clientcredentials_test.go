package handlers_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/app/clientcreds"
	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/clientip"
	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/handlers"
	"github.com/arafat-hasan/auth1/internal/http/health"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/http/server"
	"github.com/arafat-hasan/auth1/internal/testing/apitest"
)

// fakeGrant records the request and answers with res or err.
type fakeGrant struct {
	req clientcreds.Request
	res tokens.Service
	err error
}

func (f *fakeGrant) Issue(_ context.Context, r clientcreds.Request) (tokens.Service, error) {
	f.req = r
	return f.res, f.err
}

// tokenRouter serves the API with cc as the grant; nil leaves client credentials off.
func tokenRouter(t *testing.T, cc handlers.ClientCredentials) http.Handler {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	hist, err := noop.NewMeterProvider().Meter("test").Float64Histogram("d")
	if err != nil {
		t.Fatal(err)
	}
	api, err := handlers.NewAPI(keySet{}, handlers.MetadataOptions{Issuer: "https://id.example.com"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cc != nil {
		api = api.WithClientCredentials(cc)
	}
	ips, err := clientip.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	problems := problem.New(logger)
	return server.NewRouter(server.Options{
		Logger: logger, Problems: problems, ClientIP: ips,
		TracerProvider: tracenoop.NewTracerProvider(), Propagator: propagation.TraceContext{},
		RequestDuration: hist, Health: health.New(logger), Routes: gen.Routes(api, problems),
	})
}

var tokenForm = url.Values{
	"grant_type":            {clientcreds.GrantType},
	"client_assertion_type": {clientcreds.AssertionType},
	"client_assertion":      {"a.b.c"},
}

// tokenPost posts form to /v1/oauth/token and checks the exchange against the contract.
func tokenPost(t *testing.T, h http.Handler, form url.Values) response {
	t.Helper()
	req := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/oauth/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	resp := apitest.New(t).Serve(t, h, req())
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: b}
}

func TestTokenHandlerIssues(t *testing.T) {
	t.Parallel()
	g := &fakeGrant{res: tokens.Service{Token: "h.c.s", ExpiresIn: 5 * time.Minute, Scopes: []string{"tokens:introspect", "directory:read"}}}
	form := url.Values{"scope": {"directory:read tokens:introspect"}}
	for k, v := range tokenForm {
		form[k] = v
	}
	resp := tokenPost(t, tokenRouter(t, g), form)
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
	want := `{"access_token":"h.c.s","expires_in":300,"scope":"tokens:introspect directory:read","token_type":"Bearer"}` + "\n"
	if d := cmp.Diff(want, string(resp.body)); d != "" {
		t.Errorf("body (-want +got):\n%s", d)
	}
	for h, v := range map[string]string{"Cache-Control": "no-store", "Pragma": "no-cache", "Content-Type": "application/json"} {
		if got := resp.header.Get(h); got != v {
			t.Errorf("%s = %q, want %q", h, got, v)
		}
	}
	scope := "directory:read tokens:introspect"
	wantReq := clientcreds.Request{GrantType: clientcreds.GrantType, AssertionType: clientcreds.AssertionType, Assertion: "a.b.c", Scope: &scope}
	if d := cmp.Diff(wantReq, g.req); d != "" {
		t.Errorf("request (-want +got):\n%s", d)
	}
}

func TestTokenHandlerNoScope(t *testing.T) {
	t.Parallel()
	g := &fakeGrant{res: tokens.Service{Token: "h.c.s", ExpiresIn: time.Minute, Scopes: []string{"a"}}}
	if resp := tokenPost(t, tokenRouter(t, g), tokenForm); resp.status != http.StatusOK || g.req.Scope != nil {
		t.Errorf("status %d, scope %v; want 200 and none", resp.status, g.req.Scope)
	}
}

// TestTokenHandlerOAuthErrors: refusals are RFC 6749 §5.2 JSON with the code alone (never the
// reason), 401 for invalid_client and 400 otherwise, without WWW-Authenticate.
func TestTokenHandlerOAuthErrors(t *testing.T) {
	t.Parallel()
	for code, status := range map[clientcreds.OAuthCode]int{
		clientcreds.InvalidClient: 401, clientcreds.InvalidRequest: 400,
		clientcreds.InvalidScope: 400, clientcreds.UnsupportedGrantType: 400,
	} {
		t.Run(string(code), func(t *testing.T) {
			t.Parallel()
			g := &fakeGrant{err: &clientcreds.Error{Code: code, Reason: "a secret reason"}}
			resp := tokenPost(t, tokenRouter(t, g), tokenForm)
			if resp.status != status {
				t.Errorf("status %d, want %d", resp.status, status)
			}
			if want := `{"error":"` + string(code) + `"}` + "\n"; string(resp.body) != want {
				t.Errorf("body %s, want %s", resp.body, want)
			}
			if ct := resp.header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type %q", ct)
			}
			if wa := resp.header.Get("WWW-Authenticate"); wa != "" {
				t.Errorf("WWW-Authenticate %q", wa)
			}
			if got := resp.header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control %q, want no-store", got)
			}
		})
	}
}

func TestTokenHandlerUnavailable(t *testing.T) {
	t.Parallel()
	g := &fakeGrant{err: &domain.Error{Code: domain.CodeUnavailable, Detail: "down", RetryAfter: time.Second}}
	resp := tokenPost(t, tokenRouter(t, g), tokenForm)
	if resp.status != http.StatusServiceUnavailable || resp.header.Get("Content-Type") != "application/problem+json" {
		t.Errorf("status %d, %s: %s", resp.status, resp.header.Get("Content-Type"), resp.body)
	}
}

// TestTokenHandlerOff: without client credentials the endpoint is 404.
func TestTokenHandlerOff(t *testing.T) {
	t.Parallel()
	if resp := tokenPost(t, tokenRouter(t, nil), tokenForm); resp.status != http.StatusNotFound {
		t.Errorf("status %d: %s", resp.status, resp.body)
	}
}
