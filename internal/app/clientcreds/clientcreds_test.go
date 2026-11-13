package clientcreds_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/app/clientcreds"
	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/testing/assertiontest"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

const (
	issuer   = "https://id.example.test"
	endpoint = "https://id.example.test/auth/v1/oauth/token"
)

var now = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

// keys serves the clients' keys; unavailable makes every lookup ErrClientKeysUnavailable.
type keys struct {
	clients     map[string]*assertiontest.Client
	unavailable bool
	lookups     int
}

func (k *keys) Key(_ context.Context, client, kid string) (app.PublicKey, error) {
	k.lookups++
	if k.unavailable {
		return app.PublicKey{}, app.ErrClientKeysUnavailable
	}
	c, ok := k.clients[client]
	if !ok || c.Kid() != kid {
		return app.PublicKey{}, app.ErrUnknownClientKey
	}
	return c.Public(), nil
}

// assertions is client_assertions in memory.
type assertions struct {
	mu   sync.Mutex
	rows map[[2]string]time.Time
	err  error
}

func (a *assertions) Record(_ context.Context, client, jti string, exp time.Time) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return false, a.err
	}
	k := [2]string{client, jti}
	if _, ok := a.rows[k]; ok {
		return false, nil
	}
	a.rows[k] = exp
	return true, nil
}

// uow runs fn without a transaction and counts the calls.
type uow struct{ n int }

func (u *uow) Do(ctx context.Context, fn func(context.Context) error) error { u.n++; return fn(ctx) }

// issuer records what it was asked to issue.
type issuerFake struct {
	client string
	scopes []string
	err    error
}

func (i *issuerFake) IssueService(client string, scopes []string) (tokens.Service, error) {
	if i.err != nil {
		return tokens.Service{}, i.err
	}
	i.client, i.scopes = client, scopes
	return tokens.Service{Token: "tok", ExpiresAt: now.Add(5 * time.Minute), Scopes: scopes}, nil
}

type env struct {
	svc        *clientcreds.Service
	reports    *assertiontest.Client
	billing    *assertiontest.Client
	keys       *keys
	assertions *assertions
	issuer     *issuerFake
	clock      *fakes.Clock
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		reports:    assertiontest.NewClient(t, "reports", "RS256"),
		billing:    assertiontest.NewClient(t, "billing", "ES256"),
		assertions: &assertions{rows: map[[2]string]time.Time{}},
		issuer:     &issuerFake{},
		clock:      fakes.NewClock(now),
	}
	e.keys = &keys{clients: map[string]*assertiontest.Client{"reports": e.reports, "billing": e.billing}}
	svc, err := clientcreds.New(clientcreds.Options{
		Keys: e.keys, Assertions: e.assertions, UnitOfWork: &uow{}, Issuer: e.issuer, Clock: e.clock,
		Audiences: []string{endpoint, issuer},
		Clients: map[string][]string{
			"reports": {"tokens:introspect", "directory:read"},
			"billing": {"accounts:status:write"},
		},
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

func request(assertion string) clientcreds.Request {
	return clientcreds.Request{GrantType: clientcreds.GrantType, AssertionType: clientcreds.AssertionType, Assertion: assertion}
}

func (e *env) mint(t *testing.T, opts ...assertiontest.Option) string {
	t.Helper()
	return e.reports.Mint(t, endpoint, now, opts...)
}

func code(err error) clientcreds.OAuthCode {
	var oe *clientcreds.Error
	if errors.As(err, &oe) {
		return oe.Code
	}
	return ""
}

func TestIssue(t *testing.T) {
	t.Parallel()
	for _, aud := range []any{endpoint, issuer, []string{"https://other.example.test", endpoint}} {
		e := newEnv(t)
		got, err := e.svc.Issue(context.Background(), request(e.mint(t, assertiontest.Claims(map[string]any{"aud": aud}))))
		if err != nil {
			t.Fatalf("aud %v: %v", aud, err)
		}
		if got.Token != "tok" || e.issuer.client != "reports" {
			t.Errorf("aud %v: issued %v to %q", aud, got, e.issuer.client)
		}
		if d := cmp.Diff([]string{"tokens:introspect", "directory:read"}, e.issuer.scopes); d != "" {
			t.Errorf("scopes (-want +got):\n%s", d)
		}
	}
}

// TestRecordsJTIUntilExpPlusLeeway: the jti row outlives exp by the 30 s leeway (TDD-05 §2).
func TestRecordsJTIUntilExpPlusLeeway(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tok := e.mint(t, assertiontest.Claims(map[string]any{"jti": "j-1", "exp": now.Add(2 * time.Minute).Unix()}))
	if _, err := e.svc.Issue(context.Background(), request(tok)); err != nil {
		t.Fatal(err)
	}
	if got := e.assertions.rows[[2]string{"reports", "j-1"}]; !got.Equal(now.Add(2*time.Minute + 30*time.Second)) {
		t.Errorf("expires_at = %s", got)
	}
}

// The four "Done when" cases of WP-70: each is invalid_client.

func TestReplayedJTI(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tok := e.mint(t)
	if _, err := e.svc.Issue(context.Background(), request(tok)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Issue(context.Background(), request(tok)); code(err) != clientcreds.InvalidClient {
		t.Errorf("replay: err = %v, want invalid_client", err)
	}
}

func TestWrongAud(t *testing.T) {
	t.Parallel()
	for _, aud := range []any{"https://other.example.test", []string{"https://other.example.test"}, endpoint + "/", 7} {
		e := newEnv(t)
		tok := e.mint(t, assertiontest.Claims(map[string]any{"aud": aud}))
		if _, err := e.svc.Issue(context.Background(), request(tok)); code(err) != clientcreds.InvalidClient {
			t.Errorf("aud %v: err = %v, want invalid_client", aud, err)
		}
	}
}

func TestExpOverFiveMinutes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ok := e.mint(t, assertiontest.Claims(map[string]any{"exp": now.Add(5 * time.Minute).Unix()}))
	if _, err := e.svc.Issue(context.Background(), request(ok)); err != nil {
		t.Fatalf("exp 5 min after iat: %v", err)
	}
	over := e.mint(t, assertiontest.Claims(map[string]any{"exp": now.Add(5*time.Minute + time.Second).Unix()}))
	if _, err := e.svc.Issue(context.Background(), request(over)); code(err) != clientcreds.InvalidClient {
		t.Errorf("exp 5 min 1 s after iat: err = %v, want invalid_client", err)
	}
}

func TestUnknownKid(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tok := e.mint(t, assertiontest.Header(map[string]any{"kid": "rotated-away"}))
	if _, err := e.svc.Issue(context.Background(), request(tok)); code(err) != clientcreds.InvalidClient {
		t.Errorf("err = %v, want invalid_client", err)
	}
}

// TestRefusals: every other assertion check of TDD-05 §2, each changing one thing from a valid
// assertion; each is invalid_client, records no jti and issues nothing.
func TestRefusals(t *testing.T) {
	t.Parallel()
	claims := func(m map[string]any) func(*testing.T, *env) string {
		return func(t *testing.T, e *env) string { return e.mint(t, assertiontest.Claims(m)) }
	}
	header := func(m map[string]any) func(*testing.T, *env) string {
		return func(t *testing.T, e *env) string { return e.mint(t, assertiontest.Header(m)) }
	}
	tests := []struct {
		name  string
		token func(*testing.T, *env) string
	}{
		{"alg none", func(t *testing.T, e *env) string { return e.mint(t, assertiontest.Unsigned()) }},
		{"alg HS256", func(t *testing.T, e *env) string {
			return e.mint(t, assertiontest.HMAC([]byte("an attacker's secret of some length")))
		}},
		{"signed by another client's key", func(t *testing.T, e *env) string {
			return e.mint(t, assertiontest.SignedBy(e.billing))
		}},
		{"signed by an unknown key of the same alg", func(t *testing.T, e *env) string {
			return e.mint(t, assertiontest.SignedBy(assertiontest.NewClient(t, "reports", "RS256")))
		}},
		{"no kid", header(map[string]any{"kid": nil})},
		{"jku header", header(map[string]any{"jku": "https://evil.example.test/jwks"})},
		{"x5u header", header(map[string]any{"x5u": "https://evil.example.test/cert"})},
		{"crit header", header(map[string]any{"crit": []string{"exp"}})},
		{"typ at+jwt", header(map[string]any{"typ": "at+jwt"})},
		{"iss is not sub", claims(map[string]any{"sub": "billing"})},
		{"no iss", claims(map[string]any{"iss": nil})},
		{"unknown client", func(t *testing.T, _ *env) string {
			return assertiontest.NewClient(t, "stranger", "RS256").Mint(t, endpoint, now)
		}},
		{"other client's id with own key", claims(map[string]any{"iss": "billing", "sub": "billing"})},
		{"no aud", claims(map[string]any{"aud": nil})},
		{"expired", claims(map[string]any{"exp": now.Unix()})},
		{"no exp", claims(map[string]any{"exp": nil})},
		{"exp a string", claims(map[string]any{"exp": "soon"})},
		{"no iat", claims(map[string]any{"iat": nil})},
		{"iat over 30 s ahead", claims(map[string]any{"iat": now.Add(31 * time.Second).Unix(), "exp": now.Add(2 * time.Minute).Unix()})},
		{"nbf over 30 s ahead", claims(map[string]any{"nbf": now.Add(31 * time.Second).Unix()})},
		{"no jti", claims(map[string]any{"jti": nil})},
		{"empty jti", claims(map[string]any{"jti": ""})},
		{"jti of 257 characters", claims(map[string]any{"jti": strings.Repeat("é", 257)})},
		{"not a JWS", func(*testing.T, *env) string { return "not.a.jws" }},
		{"over 8 KiB", claims(map[string]any{"pad": strings.Repeat("x", 8<<10)})},
		{"padded base64", func(t *testing.T, e *env) string { return e.mint(t) + "=" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			_, err := e.svc.Issue(context.Background(), request(tt.token(t, e)))
			var oe *clientcreds.Error
			if !errors.As(err, &oe) || oe.Code != clientcreds.InvalidClient {
				t.Fatalf("err = %v, want invalid_client", err)
			}
			if len(e.assertions.rows) != 0 || e.issuer.client != "" {
				t.Errorf("a refused assertion recorded %v and issued to %q", e.assertions.rows, e.issuer.client)
			}
		})
	}
}

// TestBadHeaderLooksUpNoKey: an assertion whose header is refused never reaches the client's
// keys, so it cannot make a jwks_uri be fetched.
func TestBadHeaderLooksUpNoKey(t *testing.T) {
	t.Parallel()
	for name, opt := range map[string]assertiontest.Option{
		"alg none":  assertiontest.Unsigned(),
		"alg HS256": assertiontest.HMAC([]byte("an attacker's secret of some length")),
		"jku":       assertiontest.Header(map[string]any{"jku": "https://evil.example.test/jwks"}),
	} {
		e := newEnv(t)
		if _, err := e.svc.Issue(context.Background(), request(e.mint(t, opt))); code(err) != clientcreds.InvalidClient {
			t.Errorf("%s: err = %v", name, err)
		}
		if e.keys.lookups != 0 {
			t.Errorf("%s: %d key lookups, want 0", name, e.keys.lookups)
		}
	}
}

// TestAccepted: the edges the checks allow.
func TestAccepted(t *testing.T) {
	t.Parallel()
	tests := map[string][]assertiontest.Option{
		"typ JWT":                       {assertiontest.Header(map[string]any{"typ": "JWT"})},
		"typ client-authentication+jwt": {assertiontest.Header(map[string]any{"typ": "client-authentication+jwt"})},
		"iat 30 s ahead":                {assertiontest.Claims(map[string]any{"iat": now.Add(30 * time.Second).Unix()})},
		"nbf 30 s ahead":                {assertiontest.Claims(map[string]any{"nbf": now.Add(30 * time.Second).Unix()})},
		"jti of 256 characters":         {assertiontest.Claims(map[string]any{"jti": strings.Repeat("é", 256)})},
		"fractional times":              {assertiontest.Claims(map[string]any{"exp": float64(now.Unix()) + 60.5})},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			if _, err := e.svc.Issue(context.Background(), request(e.mint(t, opts...))); err != nil {
				t.Errorf("err = %v", err)
			}
		})
	}
	e := newEnv(t)
	if _, err := e.svc.Issue(context.Background(), request(e.billing.Mint(t, endpoint, now))); err != nil {
		t.Errorf("ES256 client: %v", err)
	}
}

// TestRefusalsIndistinguishable: the refusals differ only in their reason, which is never sent.
func TestRefusalsIndistinguishable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.mint(t, assertiontest.Header(map[string]any{"kid": "gone"}))
	b := e.mint(t, assertiontest.Claims(map[string]any{"aud": "x"}))
	_, errA := e.svc.Issue(context.Background(), request(a))
	_, errB := e.svc.Issue(context.Background(), request(b))
	var ea, eb *clientcreds.Error
	if !errors.As(errA, &ea) || !errors.As(errB, &eb) {
		t.Fatalf("errors %v, %v", errA, errB)
	}
	if ea.Code != eb.Code || ea.Reason == eb.Reason {
		t.Errorf("codes %s, %s; reasons %q, %q", ea.Code, eb.Code, ea.Reason, eb.Reason)
	}
}

func TestScope(t *testing.T) {
	t.Parallel()
	str := func(s string) *string { return &s }
	tests := []struct {
		name  string
		scope *string
		want  []string
	}{
		{"none requested", nil, []string{"tokens:introspect", "directory:read"}},
		{"empty", str(""), []string{"tokens:introspect", "directory:read"}},
		{"a subset", str("directory:read"), []string{"directory:read"}},
		{"in configured order, once", str("directory:read tokens:introspect directory:read"), []string{"tokens:introspect", "directory:read"}},
		{"unknown ones dropped", str("directory:read accounts:delete"), []string{"directory:read"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			r := request(e.mint(t))
			r.Scope = tt.scope
			if _, err := e.svc.Issue(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(tt.want, e.issuer.scopes); d != "" {
				t.Errorf("scopes (-want +got):\n%s", d)
			}
		})
	}
}

// TestEmptyGrantKeepsJTI: an empty grant is invalid_scope and records no jti, so the assertion
// may be sent again with a scope the client has.
func TestEmptyGrantKeepsJTI(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tok := e.mint(t)
	r := request(tok)
	r.Scope = new(string)
	*r.Scope = "accounts:delete"
	if _, err := e.svc.Issue(context.Background(), r); code(err) != clientcreds.InvalidScope {
		t.Fatalf("err = %v, want invalid_scope", err)
	}
	if len(e.assertions.rows) != 0 {
		t.Errorf("recorded %v", e.assertions.rows)
	}
	if _, err := e.svc.Issue(context.Background(), request(tok)); err != nil {
		t.Errorf("the same assertion afterwards: %v", err)
	}
}

func TestForm(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	valid := request(e.mint(t))
	tests := []struct {
		name   string
		change func(*clientcreds.Request)
		want   clientcreds.OAuthCode
	}{
		{"no grant type", func(r *clientcreds.Request) { r.GrantType = "" }, clientcreds.InvalidRequest},
		{"another grant type", func(r *clientcreds.Request) { r.GrantType = "password" }, clientcreds.UnsupportedGrantType},
		{"no assertion type", func(r *clientcreds.Request) { r.AssertionType = "" }, clientcreds.InvalidRequest},
		{"another assertion type", func(r *clientcreds.Request) { r.AssertionType = "urn:other" }, clientcreds.InvalidRequest},
		{"no assertion", func(r *clientcreds.Request) { r.Assertion = "" }, clientcreds.InvalidRequest},
	}
	for _, tt := range tests {
		r := valid
		tt.change(&r)
		if _, err := e.svc.Issue(context.Background(), r); code(err) != tt.want {
			t.Errorf("%s: err = %v, want %s", tt.name, err, tt.want)
		}
	}
}

// TestUnavailable: keys that cannot be fetched, a failed store and no signing key are UNAVAILABLE
// (503), not an OAuth error.
func TestUnavailable(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*env){
		"keys":        func(e *env) { e.keys.unavailable = true },
		"store":       func(e *env) { e.assertions.err = &domain.Error{Code: domain.CodeUnavailable} },
		"signing key": func(e *env) { e.issuer.err = app.ErrNoSigningKey },
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			setup(e)
			_, err := e.svc.Issue(context.Background(), request(e.mint(t)))
			var de *domain.Error
			if !errors.As(err, &de) || de.Code != domain.CodeUnavailable || code(err) != "" {
				t.Errorf("err = %v, want UNAVAILABLE", err)
			}
		})
	}
}

func TestNewRefusesMissing(t *testing.T) {
	t.Parallel()
	if s, err := clientcreds.New(clientcreds.Options{}); err == nil || s != nil {
		t.Errorf("New = %v, %v; want an error", s, err)
	}
}
