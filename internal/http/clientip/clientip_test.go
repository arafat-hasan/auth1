package clientip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

var trusted = []string{"10.0.0.0/8", "2001:db8:ffff::/48"}

func mustNew(t testing.TB, cidrs []string) *Resolver {
	t.Helper()
	r, err := New(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolve(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		trusted []string
		peer    string
		xff     []string
		want    string
	}{
		{"no trusted proxies ignore the header", nil, "203.0.113.9:4000", []string{"198.51.100.1"}, "203.0.113.9"},
		{"untrusted peer is the client", trusted, "203.0.113.9:4000", []string{"198.51.100.1"}, "203.0.113.9"},
		{"no header behind a trusted proxy", trusted, "10.0.0.2:80", nil, "10.0.0.2"},
		{"one trusted proxy", trusted, "10.0.0.2:80", []string{"198.51.100.1"}, "198.51.100.1"},
		{"spoofed entries left of the client", trusted, "10.0.0.2:80", []string{"1.1.1.1, 2.2.2.2, 198.51.100.1, 10.0.0.3"}, "198.51.100.1"},
		{"every hop trusted gives the left-most", trusted, "10.0.0.2:80", []string{"10.1.1.1, 10.0.0.3"}, "10.1.1.1"},
		{"headers are concatenated in order", trusted, "10.0.0.2:80", []string{"1.1.1.1, 198.51.100.1", "10.0.0.3"}, "198.51.100.1"},
		{"IPv4 with a port", trusted, "10.0.0.2:80", []string{"198.51.100.1:443"}, "198.51.100.1"},
		{"bracketed IPv6", trusted, "10.0.0.2:80", []string{"[2001:db8::7]"}, "2001:db8::7"},
		{"bracketed IPv6 with a port", trusted, "10.0.0.2:80", []string{"[2001:db8::7]:443"}, "2001:db8::7"},
		{"bare IPv6", trusted, "10.0.0.2:80", []string{"2001:db8::7"}, "2001:db8::7"},
		{"zone is dropped", trusted, "10.0.0.2:80", []string{"fe80::1%eth0"}, "fe80::1"},
		{"IPv4-mapped entry read as IPv4", trusted, "10.0.0.2:80", []string{"::ffff:198.51.100.1"}, "198.51.100.1"},
		{"IPv4-mapped trusted peer", trusted, "[::ffff:10.0.0.2]:80", []string{"198.51.100.1"}, "198.51.100.1"},
		{"IPv4-mapped trusted entry", trusted, "10.0.0.2:80", []string{"198.51.100.1, ::ffff:10.0.0.3"}, "198.51.100.1"},
		{"empty entries skipped", trusted, "10.0.0.2:80", []string{"198.51.100.1, , ", " "}, "198.51.100.1"},
		{"garbage ends the walk at the trusted hop", trusted, "10.0.0.2:80", []string{"198.51.100.1, unknown, 10.0.0.3"}, "10.0.0.3"},
		{"garbage next to the peer gives the peer", trusted, "10.0.0.2:80", []string{"198.51.100.1, _hidden"}, "10.0.0.2"},
		{"IPv6 trusted prefix", trusted, "[2001:db8:ffff:1::2]:80", []string{"2001:db8:1::5"}, "2001:db8:1::5"},
		{"outside the IPv6 trusted prefix", trusted, "[2001:db8:fffe::2]:80", []string{"2001:db8:1::5"}, "2001:db8:fffe::2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := mustNew(t, tc.trusted).Resolve(tc.peer, tc.xff)
			if want := netip.MustParseAddr(tc.want); got != want {
				t.Errorf("Resolve(%q, %q) = %v, want %v", tc.peer, tc.xff, got, want)
			}
		})
	}
}

func TestResolveBadPeer(t *testing.T) {
	t.Parallel()
	if got := mustNew(t, trusted).Resolve("pipe", []string{"198.51.100.1"}); got.IsValid() {
		t.Errorf("Resolve with a peer that is not an address = %v, want the zero Addr", got)
	}
}

func TestNewRefusesBadCIDR(t *testing.T) {
	t.Parallel()
	for _, c := range []string{"10.0.0.0", "10.0.0.0/33", "proxy", ""} {
		if _, err := New([]string{c}); err == nil {
			t.Errorf("New(%q) succeeded", c)
		}
	}
}

func TestMiddlewareStoresIP(t *testing.T) {
	t.Parallel()
	var got netip.Addr
	h := mustNew(t, trusted).Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = From(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:80"
	req.Header.Add("X-Forwarded-For", "198.51.100.1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if want := netip.MustParseAddr("198.51.100.1"); got != want {
		t.Errorf("From = %v, want %v", got, want)
	}
}

func TestFromWith(t *testing.T) {
	t.Parallel()
	if got := From(context.Background()); got.IsValid() {
		t.Errorf("From(empty) = %v, want the zero Addr", got)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	if got := From(With(context.Background(), ip)); got != ip {
		t.Errorf("From(With) = %v, want %v", got, ip)
	}
}
