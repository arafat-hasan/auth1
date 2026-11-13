package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/testing/apitest"
	"github.com/arafat-hasan/auth1/internal/testing/assertiontest"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
	"github.com/arafat-hasan/auth1/internal/testing/redistest"
)

// The example's issuer, and so the audience a client assertion names.
const (
	exampleIssuer = "https://id.example.com"
	tokenEndpoint = exampleIssuer + "/v1/oauth/token"
)

// withClientCredentials turns on mode both with the service client "reports", its keys at
// keys (a jwks_file path, or an https jwks_uri), granted tokens:introspect and directory:read.
func withClientCredentials(keys string) func(t *testing.T, cfg string) string {
	return func(t *testing.T, cfg string) string {
		t.Helper()
		file, uri := keys, ""
		if strings.HasPrefix(keys, "https://") {
			file, uri = "", keys
		}
		out := cfg
		for _, r := range [][2]string{
			{"  mode: mesh ", "  mode: both "},
			{`        jwks_file: ""  `, `        jwks_file: "` + file + `"  `},
			{"        jwks_uri: https://reports.example.com/.well-known/jwks.json", `        jwks_uri: "` + uri + `"`},
			{"  callers:                                # scopes by service identity; no default\n",
				"  callers:\n    - identity: reports\n      scopes: [tokens:introspect, directory:read]\n"},
		} {
			if !strings.Contains(out, r[0]) {
				t.Fatalf("the example has no %q; update the test", r[0])
			}
			out = strings.Replace(out, r[0], r[1], 1)
		}
		return withSecureClient(t, out)
	}
}

// ccServer is the sign-in server with client credentials on, for the client c.
type ccServer struct {
	signInServer
	client *assertiontest.Client
}

// startCCServer starts serve with client credentials on for a new ES256 client "reports" whose
// keys are in a jwks_file; keys, when not empty, replaces the file with a jwks_uri.
func startCCServer(t *testing.T, keys string, opts ...func(*serveDeps)) ccServer {
	t.Helper()
	c := assertiontest.NewClient(t, "reports", "ES256")
	if keys == "" {
		keys = filepath.Join(t.TempDir(), "reports.jwks.json")
		if err := os.WriteFile(keys, c.JWKS(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rds := redistest.NewServer(t)
	s := startRegServerFull(t, withClientCredentials(keys), opts,
		"AUTH1_REDIS_ADDRESS="+rds.Addr(),
		"AUTH1_RATE_LIMITS_REGISTRATION_IP_LIMIT=100", "AUTH1_RATE_LIMITS_SIGN_IN_IP_LIMIT=1000",
		"AUTH1_RATE_LIMITS_SEND_IP_LIMIT=100", "AUTH1_RATE_LIMITS_VERIFY_IP_LIMIT=100")
	waitReady(t, s.api, http.StatusOK, "ok", 10*time.Second)
	return ccServer{signInServer: signInServer{regServer: s, redis: rds}, client: c}
}

// token posts form to /v1/oauth/token and checks the exchange against the contract.
func (s ccServer) token(t *testing.T, form url.Values) answer {
	t.Helper()
	build := func(base string) *http.Request {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/v1/oauth/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}
	resp, err := http.DefaultClient.Do(build(s.api))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	apitest.New(t).Check(t, build(""), resp)
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	a := answer{status: resp.StatusCode, header: resp.Header, raw: raw}
	if err := json.Unmarshal(raw, &a.body); err != nil {
		t.Fatalf("token body %s: %v", raw, err)
	}
	return a
}

func assertionForm(assertion string) url.Values {
	return url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
}

// wantOAuth checks a is the RFC 6749 error code with status.
func (a answer) wantOAuth(t *testing.T, status int, code string) {
	t.Helper()
	if a.status != status || a.body["error"] != code || len(a.body) != 1 {
		t.Errorf("answer %d %s, want %d {error: %s}", a.status, a.raw, status, code)
	}
}

// introspectBearer posts to /v1/introspect with the bearer token, or none for "".
func introspectBearer(t *testing.T, api, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, api+"/v1/introspect", strings.NewReader("token=abc"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// header decodes a compact JWS's protected header, without checking it.
func header(t *testing.T, token string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// TestClientCredentialsThroughAPI: a client assertion gets a service token (TDD-05 §2) that the
// caller resolver accepts on a service operation; its replay, a wrong aud, an exp over 5 minutes
// and an unknown kid are each invalid_client.
func TestClientCredentialsThroughAPI(t *testing.T) {
	s := startCCServer(t, "")
	assertion := s.client.Mint(t, tokenEndpoint, time.Now())
	form := assertionForm(assertion)
	form.Set("scope", "tokens:introspect")
	a := s.token(t, form)
	a.want(t, http.StatusOK, "")
	if a.header.Get("Cache-Control") != "no-store" || a.body["token_type"] != "Bearer" ||
		a.body["expires_in"] != float64(300) || a.body["scope"] != "tokens:introspect" {
		t.Errorf("answer %s, Cache-Control %q", a.raw, a.header.Get("Cache-Control"))
	}
	tok, _ := a.body["access_token"].(string)
	if h := header(t, tok); h["typ"] != "at+jwt" || h["kid"] == nil {
		t.Errorf("header %v", h)
	}
	c := claims(t, tok)
	if c["iss"] != exampleIssuer || c["aud"] != "auth1-services" || c["sub"] != "reports" ||
		c["client_id"] != "reports" || c["scope"] != "tokens:introspect" || len(c) != 9 {
		t.Errorf("claims %v", c)
	}

	if code, body := introspectBearer(t, s.api, tok); code != http.StatusNotImplemented {
		t.Errorf("service token on a service operation: %d %s, want the stub's 501", code, body)
	}
	if code, _ := introspectBearer(t, s.api, ""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", code)
	}

	s.token(t, assertionForm(assertion)).wantOAuth(t, http.StatusUnauthorized, "invalid_client")
	now := time.Now()
	for name, bad := range map[string]string{
		"wrong aud":      s.client.Mint(t, "https://other.example.com/v1/oauth/token", now),
		"exp over 5 min": s.client.Mint(t, tokenEndpoint, now, assertiontest.Claims(map[string]any{"exp": now.Add(6 * time.Minute).Unix()})),
		"unknown kid":    s.client.Mint(t, tokenEndpoint, now, assertiontest.Header(map[string]any{"kid": "rotated"})),
	} {
		t.Run(name, func(t *testing.T) {
			s.token(t, assertionForm(bad)).wantOAuth(t, http.StatusUnauthorized, "invalid_client")
		})
	}

	var rows int
	if err := s.db.QueryRowContext(t.Context(), "SELECT count(*) FROM client_assertions WHERE client_id = 'reports'").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("%d client_assertions rows, want 1", rows)
	}
}

// TestClientCredentialsConcurrentReplay: one assertion sent eight times at once yields exactly one
// token.
func TestClientCredentialsConcurrentReplay(t *testing.T) {
	s := startCCServer(t, "")
	assertion := s.client.Mint(t, tokenEndpoint, time.Now())
	var mu sync.Mutex
	statuses := map[int]int{}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			resp, err := http.PostForm(s.api+"/v1/oauth/token", assertionForm(assertion)) //nolint:noctx // a test
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
			mu.Lock()
			statuses[resp.StatusCode]++
			mu.Unlock()
		})
	}
	close(start)
	wg.Wait()
	if statuses[http.StatusOK] != 1 || statuses[http.StatusUnauthorized] != 7 {
		t.Errorf("statuses %v, want one 200 and seven 401", statuses)
	}
}

// TestUserTokenRefusedOnServiceEndpoint: a user's access token is no service token (SDD D-13).
func TestUserTokenRefusedOnServiceEndpoint(t *testing.T) {
	s := startCCServer(t, "")
	s.account(t, "ada@example.org")
	a := s.signIn(t, "web", "ada@example.org", regPassword, "")
	a.want(t, http.StatusOK, "")
	tok, _ := a.body["access_token"].(string)
	if code, body := introspectBearer(t, s.api, tok); code != http.StatusUnauthorized || !strings.Contains(body, `"TOKEN_INVALID"`) {
		t.Errorf("user token on a service operation: %d %s, want 401 TOKEN_INVALID", code, body)
	}
}

// TestJWKSURIOverTLS: a client's keys may come from an https jwks_uri.
func TestJWKSURIOverTLS(t *testing.T) {
	var jwks []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(srv.Close)
	c := assertiontest.NewClient(t, "reports", "RS256")
	jwks = c.JWKS()
	s := startCCServer(t, srv.URL+"/jwks.json", func(d *serveDeps) { d.jwksClient = srv.Client() })
	s.token(t, assertionForm(c.Mint(t, tokenEndpoint, time.Now()))).want(t, http.StatusOK, "")
}

// TestTokenEndpointOffInMeshMode: the example's mode is mesh, so the endpoint is 404.
func TestTokenEndpointOffInMeshMode(t *testing.T) {
	api := startServe(t, append(dsnEnv(t, pgtest.DSN(t)), promoteAtOnce))
	resp, err := http.PostForm(api+"/v1/oauth/token", assertionForm("a.b.c")) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", resp.StatusCode)
	}
}

func TestLoadClientKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "good.json"), filepath.Join(dir, "bad.json")
	writeFile(t, good, string(assertiontest.NewClient(t, "a", "ES256").JWKS()))
	writeFile(t, bad, `{"keys":[]}`)
	cfg := config.Default()
	cfg.ServiceAuth.Mode = config.ServiceAuthBoth
	cfg.ServiceAuth.ClientCredentials.Clients = []config.ServiceClient{
		{ID: "a", JWKSFile: good}, {ID: "b", JWKSFile: bad}, {ID: "c", JWKSURI: "https://c.example.com/jwks"},
	}
	logger := slog.New(slog.DiscardHandler)
	store, problems := loadClientKeys(&cfg, nil, logger)
	if store != nil || len(problems) != 1 || problems[0].Path != "service_auth.client_credentials.clients[1].jwks_file" {
		t.Errorf("store %v, problems %v", store, problems)
	}
	cfg.ServiceAuth.ClientCredentials.Clients = cfg.ServiceAuth.ClientCredentials.Clients[:1]
	if store, problems := loadClientKeys(&cfg, nil, logger); store == nil || len(problems) != 0 {
		t.Errorf("store %v, problems %v", store, problems)
	}
	cfg.ServiceAuth.Mode = config.ServiceAuthMesh
	cfg.ServiceAuth.ClientCredentials.Clients = []config.ServiceClient{{ID: "b", JWKSFile: bad}}
	if store, problems := loadClientKeys(&cfg, nil, logger); store != nil || len(problems) != 0 {
		t.Errorf("mesh mode: store %v, problems %v", store, problems)
	}
}

// TestConfigCheckBadJWKSFile: config check refuses a service client's jwks_file with no usable key.
func TestConfigCheckBadJWKSFile(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	example, err := os.ReadFile("config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	writeFile(t, bad, `{"keys":[]}`)
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, withClientCredentials(bad)(t, string(example)))
	out, err := runConfigCheck(t, path)
	if !errors.Is(err, errConfigInvalid) || !strings.Contains(out, "  - service_auth.client_credentials.clients[0].jwks_file: ") {
		t.Errorf("config check = %v\n%s", err, out)
	}
}
