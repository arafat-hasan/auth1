package caller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/metric/noop"

	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/problem"
)

var sidecars = []string{"127.0.0.1/32", "::1/128"}

// withDeps returns o with a discarding writer, audit, counter and logger where it has none.
func withDeps(t *testing.T, o Options) Options {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	if o.Problems == nil {
		o.Problems = problem.New(logger)
	}
	if o.Audit == nil {
		o.Audit = &audit{}
	}
	if o.Denied == nil {
		c, err := noop.NewMeterProvider().Meter("test").Int64Counter("denied")
		if err != nil {
			t.Fatal(err)
		}
		o.Denied = c
	}
	if o.Logger == nil {
		o.Logger = logger
	}
	return o
}

// mustNew returns the resolver for o, given the dependencies it lacks, failing t if New refuses it.
func mustNew(t *testing.T, o Options) *Resolver {
	t.Helper()
	r, err := New(withDeps(t, o))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// verified returns a TLS state whose verified chain's leaf has the URI SANs uris.
func verified(t *testing.T, uris ...string) *tls.ConnectionState {
	t.Helper()
	leaf := &x509.Certificate{}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		leaf.URIs = append(leaf.URIs, u)
	}
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, {}}}}
}

func TestWorkloadIdentity(t *testing.T) {
	t.Parallel()
	xfcc := Options{Source: SourceHeader, Header: "X-Forwarded-Client-Cert", Format: FormatXFCC, TrustedSidecars: sidecars}
	plain := Options{Source: SourceHeader, Header: "l5d-client-id", Format: FormatPlain, TrustedSidecars: sidecars}
	peer := Options{Source: SourcePeerCert, Header: "X-Forwarded-Client-Cert", TrustedSidecars: sidecars}
	for _, tc := range []struct {
		name    string
		o       Options
		remote  string
		headers map[string][]string
		tls     *tls.ConnectionState
		want    string // "" for no identity
	}{
		{"xfcc from a sidecar", xfcc, "127.0.0.1:41000", map[string][]string{"X-Forwarded-Client-Cert": {"URI=" + spiffe}}, nil, spiffe},
		{"xfcc from IPv6 loopback", xfcc, "[::1]:41000", map[string][]string{"X-Forwarded-Client-Cert": {"URI=" + spiffe}}, nil, spiffe},
		{"xfcc from a mapped sidecar", xfcc, "[::ffff:127.0.0.1]:41000", map[string][]string{"X-Forwarded-Client-Cert": {"URI=" + spiffe}}, nil, spiffe},
		{"xfcc from another address is ignored", xfcc, "10.1.2.3:41000", map[string][]string{"X-Forwarded-Client-Cert": {"URI=" + spiffe}}, nil, ""},
		{"xfcc from an unparsable peer", xfcc, "sidecar", map[string][]string{"X-Forwarded-Client-Cert": {"URI=" + spiffe}}, nil, ""},
		{"xfcc with two elements", xfcc, "127.0.0.1:41000", map[string][]string{"X-Forwarded-Client-Cert": {"URI=" + spiffe + ",URI=spiffe://b"}}, nil, ""},
		{"no header", xfcc, "127.0.0.1:41000", nil, nil, ""},
		{"header source ignores the peer certificate", xfcc, "127.0.0.1:41000", nil, verified(t, spiffe), ""},
		{"plain from a sidecar", plain, "127.0.0.1:41000", map[string][]string{"L5d-Client-Id": {"billing.ns.serviceaccount.identity.linkerd.cluster.local"}}, nil, "billing.ns.serviceaccount.identity.linkerd.cluster.local"},
		{"plain from another address is ignored", plain, "192.0.2.7:41000", map[string][]string{"L5d-Client-Id": {"billing"}}, nil, ""},
		{"plain with two values", plain, "127.0.0.1:41000", map[string][]string{"L5d-Client-Id": {"billing", "edge"}}, nil, ""},
		{"plain empty", plain, "127.0.0.1:41000", map[string][]string{"L5d-Client-Id": {""}}, nil, ""},
		{"peer certificate", peer, "10.1.2.3:41000", nil, verified(t, spiffe, "spiffe://second"), spiffe},
		{"peer certificate without a URI", peer, "10.1.2.3:41000", nil, verified(t), ""},
		{"peer certificate not verified", peer, "10.1.2.3:41000", nil, &tls.ConnectionState{}, ""},
		{"peer certificate with an empty chain", peer, "10.1.2.3:41000", nil, &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}, ""},
		{"no TLS", peer, "10.1.2.3:41000", nil, nil, ""},
		{"peer_cert ignores the header", peer, "127.0.0.1:41000", map[string][]string{"X-Forwarded-Client-Cert": {"URI=" + spiffe}}, nil, ""},
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/introspect", nil)
		req.RemoteAddr = tc.remote
		req.TLS = tc.tls
		for k, vs := range tc.headers {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		got, ok := mustNew(t, tc.o).workloadIdentity(req)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: workloadIdentity = %q, %v; want %q", tc.name, got, ok, tc.want)
		}
	}
}

func TestNewRejectsBadCIDR(t *testing.T) {
	t.Parallel()
	for _, cidr := range []string{"127.0.0.1", "localhost", "10.0.0.0/33", "", "::ffff:0:0/80"} {
		_, err := New(withDeps(t, Options{TrustedSidecars: []string{"::1/128", cidr}}))
		if err == nil || !strings.Contains(err.Error(), "trusted sidecar") {
			t.Errorf("New(trusted sidecar %q) = %v, want a trusted sidecar error", cidr, err)
		}
	}
}

func TestCallerHas(t *testing.T) {
	t.Parallel()
	c := Caller{Kind: KindWorkload, ID: spiffe, Scopes: []string{"directory:read"}}
	if !c.Has("directory:read") {
		t.Error("Has(directory:read) = false")
	}
	for _, s := range []string{"directory:read:identifiers", "Directory:read", "", "tokens:introspect"} {
		if c.Has(s) {
			t.Errorf("Has(%q) = true", s)
		}
	}
}

// TestNewRequiresDependencies: a missing dependency fails at start-up, not as a panic on the first
// refused request.
func TestNewRequiresDependencies(t *testing.T) {
	t.Parallel()
	for name, drop := range map[string]func(*Options){
		"Problems": func(o *Options) { o.Problems = nil },
		"Audit":    func(o *Options) { o.Audit = nil },
		"Denied":   func(o *Options) { o.Denied = nil },
		"Logger":   func(o *Options) { o.Logger = nil },
	} {
		o := withDeps(t, Options{})
		drop(&o)
		if _, err := New(o); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("New without %s = %v, want an error naming it", name, err)
		}
	}
}

// TestNewRequiresHeader: a mode that reads the mesh identity from a header needs the header's name.
func TestNewRequiresHeader(t *testing.T) {
	t.Parallel()
	for _, m := range []Mode{ModeMesh, ModeBoth} {
		if _, err := New(withDeps(t, Options{Mode: m, Source: SourceHeader})); err == nil {
			t.Errorf("mode %v with no header: New accepted it", m)
		}
		if _, err := New(withDeps(t, Options{Mode: m, Source: SourcePeerCert})); err != nil {
			t.Errorf("mode %v, peer_cert with no header: %v", m, err)
		}
	}
	for _, m := range []Mode{ModeNone, ModeClientCredentials} {
		if _, err := New(withDeps(t, Options{Mode: m, Source: SourceHeader})); err != nil {
			t.Errorf("mode %v with no header: %v", m, err)
		}
	}
}

// TestNewCopiesCallers: changing the caller table after New changes no authorisation.
func TestNewCopiesCallers(t *testing.T) {
	t.Parallel()
	callers := map[string][]string{spiffe: {"directory:read"}}
	r := mustNew(t, Options{Mode: ModeMesh, Header: "X-Forwarded-Client-Cert", TrustedSidecars: sidecars, Callers: callers})
	callers[spiffe][0] = "tokens:introspect"
	callers["spiffe://other"] = []string{"tokens:introspect"}
	req := httptest.NewRequest(http.MethodPost, "/v1/introspect", nil)
	req.RemoteAddr = "127.0.0.1:41000"
	req.Header.Set("X-Forwarded-Client-Cert", "URI="+spiffe)
	c, ok := r.resolve(req, gen.Operations["introspectToken"])
	if !ok || c.Has("tokens:introspect") || !c.Has("directory:read") {
		t.Errorf("after changing the table: %+v, %v; want directory:read only", c, ok)
	}
}

// TestMappedSidecarCIDR: an IPv4-mapped sidecar range matches the IPv4 peers it names.
func TestMappedSidecarCIDR(t *testing.T) {
	t.Parallel()
	r := mustNew(t, Options{TrustedSidecars: []string{"::ffff:127.0.0.1/128", "::ffff:10.0.0.0/104"}})
	for remote, want := range map[string]bool{
		"127.0.0.1:41000":          true,
		"[::ffff:127.0.0.1]:41000": true,
		"10.9.8.7:41000":           true,
		"127.0.0.2:41000":          false,
		"11.0.0.1:41000":           false,
	} {
		if got := r.fromSidecar(remote); got != want {
			t.Errorf("fromSidecar(%s) = %v, want %v", remote, got, want)
		}
	}
}

// TestFromCopiesScopes: a handler changing the scopes it read does not change them for the next
// reader of the same request.
func TestFromCopiesScopes(t *testing.T) {
	t.Parallel()
	ctx := with(context.Background(), Caller{Kind: KindWorkload, ID: spiffe, Scopes: []string{"directory:read"}})
	c, _ := From(ctx)
	c.Scopes[0] = "accounts:delete"
	if again, _ := From(ctx); !again.Has("directory:read") || again.Has("accounts:delete") {
		t.Errorf("From after a change: %+v", again)
	}
}
