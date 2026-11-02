package clientip

import (
	"strings"
	"testing"
)

func FuzzResolve(f *testing.F) {
	for _, s := range []string{
		"198.51.100.1", "1.1.1.1, 2.2.2.2, 198.51.100.1, 10.0.0.3", "10.1.1.1, 10.0.0.3",
		"[2001:db8::7]:443", "fe80::1%eth0", "::ffff:198.51.100.1", "198.51.100.1, , ",
		"unknown, 10.0.0.3", "[", "]:", "%", "::ffff:10.0.0.3", "1.2.3.4:99999", "[1.2.3.4]",
	} {
		f.Add("10.0.0.2:80", s, true)
		f.Add("203.0.113.9:4000", s, false)
	}
	f.Fuzz(func(t *testing.T, peer, header string, trust bool) {
		var cidrs []string
		if trust {
			cidrs = trusted
		}
		r := mustNew(t, cidrs)
		xff := strings.Split(header, "\n")
		got := r.Resolve(peer, xff)
		if again := r.Resolve(peer, xff); again != got {
			t.Fatalf("not deterministic: %v then %v", got, again)
		}
		p, ok := parsePeer(peer)
		if !ok {
			if got.IsValid() {
				t.Fatalf("peer %q is not an address but Resolve gave %v", peer, got)
			}
			return
		}
		if got == p {
			return
		}
		if !trust {
			t.Fatalf("with no trusted proxies Resolve gave %v, want the peer %v", got, p)
		}
		for _, h := range xff {
			for _, e := range strings.Split(h, ",") {
				if a, ok := parseEntry(strings.TrimSpace(e)); ok && a == got {
					return
				}
			}
		}
		t.Fatalf("Resolve gave %v, which is neither the peer nor an entry of %q", got, xff)
	})
}
