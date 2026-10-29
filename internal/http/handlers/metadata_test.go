package handlers_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/handlers"
	"github.com/arafat-hasan/auth1/internal/http/health"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/http/server"
	"github.com/arafat-hasan/auth1/internal/testing/apitest"
)

// keySet is a fixed app.PublicKeys.
type keySet struct {
	keys   []app.PublicKey
	synced bool
}

func (s keySet) Key(kid string) (app.PublicKey, bool) {
	for _, k := range s.keys {
		if k.Kid == kid {
			return k, true
		}
	}
	return app.PublicKey{}, false
}

func (s keySet) Published() ([]app.PublicKey, bool) { return s.keys, s.synced }

// testKeys returns an RS256 and an ES256 public key, each with its RFC 7638 kid from jwx.
func testKeys(t *testing.T) []app.PublicKey {
	t.Helper()
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := func(pub any) string {
		k, err := jwk.Import(pub)
		if err != nil {
			t.Fatal(err)
		}
		sum, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(sum)
	}
	return []app.PublicKey{
		{Kid: kid(&r.PublicKey), Alg: "RS256", Key: &r.PublicKey},
		{Kid: kid(&e.PublicKey), Alg: "ES256", Key: &e.PublicKey},
	}
}

func router(t *testing.T, keys app.PublicKeys, m handlers.MetadataOptions) http.Handler {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	hist, err := noop.NewMeterProvider().Meter("test").Float64Histogram("d")
	if err != nil {
		t.Fatal(err)
	}
	api, err := handlers.NewAPI(keys, m)
	if err != nil {
		t.Fatal(err)
	}
	problems := problem.New(logger)
	return server.NewRouter(server.Options{
		BasePath: m.BasePath, Logger: logger, Problems: problems,
		TracerProvider: tracenoop.NewTracerProvider(), Propagator: propagation.TraceContext{},
		RequestDuration: hist, Health: health.New(logger),
		Routes: gen.Routes(api, problems),
	})
}

var defaultMetadata = handlers.MetadataOptions{Issuer: "https://id.example.com"}

// response is a served response, its body read.
type response struct {
	status int
	header http.Header
	body   []byte
}

// get serves GET basePath+path with h and checks the exchange against the contract, whose paths
// carry no base path.
func get(t *testing.T, h http.Handler, basePath, path string, header http.Header) response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, basePath+path, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	contractReq := req.Clone(req.Context())
	contractReq.URL.Path = path
	apitest.New(t).Check(t, contractReq, resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: body}
}

func TestJWKS(t *testing.T) {
	t.Parallel()
	keys := testKeys(t)
	resp := get(t, router(t, keySet{keys: keys, synced: true}, defaultMetadata), "", "/.well-known/jwks.json", nil)
	body := resp.body
	if resp.status != http.StatusOK {
		t.Fatalf("status %d, body %s", resp.status, body)
	}
	if got := resp.header.Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control %q", got)
	}
	sum := sha256.Sum256(body)
	if got, want := resp.header.Get("ETag"), `"`+base64.RawURLEncoding.EncodeToString(sum[:])+`"`; got != want {
		t.Errorf("ETag %s, want the strong tag over the body %s", got, want)
	}

	set, err := jwk.Parse(body)
	if err != nil {
		t.Fatalf("parse the JWKS: %v", err)
	}
	if set.Len() != len(keys) {
		t.Fatalf("%d keys, want %d", set.Len(), len(keys))
	}
	for i, want := range keys {
		k, _ := set.Key(i)
		kid, _ := k.KeyID()
		sum, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if kid != want.Kid || base64.RawURLEncoding.EncodeToString(sum) != want.Kid {
			t.Errorf("keys[%d]: kid %s, thumbprint %x; want %s for both", i, kid, sum, want.Kid)
		}
		var raw any
		if err := jwk.Export(k, &raw); err != nil {
			t.Fatal(err)
		}
		if !raw.(interface{ Equal(crypto.PublicKey) bool }).Equal(want.Key) {
			t.Errorf("keys[%d]: the JWK is not the published key", i)
		}
	}
}

func TestJWKSNotModified(t *testing.T) {
	t.Parallel()
	h := router(t, keySet{keys: testKeys(t), synced: true}, defaultMetadata)
	etag := get(t, h, "", "/.well-known/jwks.json", nil).header.Get("ETag")
	tests := []struct {
		name, ifNoneMatch string
		want              int
	}{
		{"same tag", etag, http.StatusNotModified},
		{"weak form", "W/" + etag, http.StatusNotModified},
		{"in a list", `"other", ` + etag, http.StatusNotModified},
		{"any", "*", http.StatusNotModified},
		{"other tag", `"other"`, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := get(t, h, "", "/.well-known/jwks.json", http.Header{"If-None-Match": {tt.ifNoneMatch}})
			body := resp.body
			if resp.status != tt.want {
				t.Fatalf("status %d, want %d", resp.status, tt.want)
			}
			if resp.header.Get("ETag") != etag || resp.header.Get("Cache-Control") != "public, max-age=300" {
				t.Errorf("headers %v, want the ETag and Cache-Control", resp.header)
			}
			if tt.want == http.StatusNotModified && len(body) != 0 {
				t.Errorf("304 with a body %q", body)
			}
		})
	}
}

func TestJWKSUnavailable(t *testing.T) {
	t.Parallel()
	resp := get(t, router(t, keySet{}, defaultMetadata), "", "/.well-known/jwks.json", nil)
	body := resp.body
	if resp.status != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.status)
	}
	var p struct{ Code string }
	if err := json.Unmarshal(body, &p); err != nil || p.Code != "UNAVAILABLE" {
		t.Errorf("body %s, want UNAVAILABLE", body)
	}
}

func TestServerMetadata(t *testing.T) {
	t.Parallel()
	ptr := func(v string) *string { return &v }
	list := func(v ...string) *[]string { return &v }
	tests := []struct {
		name string
		m    handlers.MetadataOptions
		want gen.ServerMetadata
	}{
		{
			name: "mesh only",
			m:    handlers.MetadataOptions{Issuer: "https://id.example.com"},
			want: gen.ServerMetadata{
				Issuer:                "https://id.example.com",
				JwksUri:               "https://id.example.com/.well-known/jwks.json",
				IntrospectionEndpoint: ptr("https://id.example.com/v1/introspect"),
			},
		},
		{
			name: "base path and client credentials",
			m:    handlers.MetadataOptions{Issuer: "https://example.com/auth", BasePath: "/auth", ClientCredentials: true},
			want: gen.ServerMetadata{
				Issuer:                            "https://example.com/auth",
				JwksUri:                           "https://example.com/auth/.well-known/jwks.json",
				IntrospectionEndpoint:             ptr("https://example.com/auth/v1/introspect"),
				TokenEndpoint:                     ptr("https://example.com/auth/v1/oauth/token"),
				TokenEndpointAuthMethodsSupported: list("private_key_jwt"),
				TokenEndpointAuthSigningAlgValuesSupported: list("RS256", "ES256"),
				GrantTypesSupported:                        list("client_credentials"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := get(t, router(t, keySet{}, tt.m), tt.m.BasePath, "/.well-known/oauth-authorization-server", nil)
			body := resp.body
			if resp.status != http.StatusOK {
				t.Fatalf("status %d, body %s", resp.status, body)
			}
			var got gen.ServerMetadata
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("metadata (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewAPIRefusesBadIssuer(t *testing.T) {
	t.Parallel()
	if _, err := handlers.NewAPI(keySet{}, handlers.MetadataOptions{Issuer: "id.example.com"}); err == nil {
		t.Error("NewAPI accepted a relative issuer")
	}
}
