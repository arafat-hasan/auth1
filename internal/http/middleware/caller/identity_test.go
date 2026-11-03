package caller

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

var sidecars = []string{"127.0.0.1/32", "::1/128"}

// mustNew returns the resolver for o, failing t if New refuses it.
func mustNew(t *testing.T, o Options) *Resolver {
	t.Helper()
	r, err := New(o)
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
	for _, cidr := range []string{"127.0.0.1", "localhost", "10.0.0.0/33", ""} {
		if _, err := New(Options{TrustedSidecars: []string{"::1/128", cidr}}); err == nil {
			t.Errorf("New accepted trusted sidecar %q", cidr)
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
