package clientip

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// Header is the forwarding header read through trusted proxies.
const Header = "X-Forwarded-For"

type ctxKey struct{}

// Resolver finds client IPs through a set of trusted proxies.
type Resolver struct {
	trusted []netip.Prefix
}

// New returns a resolver trusting the proxies in cidrs (http.trusted_proxies). It refuses an
// entry that is not a CIDR.
func New(cidrs []string) (*Resolver, error) {
	r := &Resolver{}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: not a CIDR", c)
		}
		// Addresses are compared as IPv4 when they map one, so a mapped prefix is too.
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		r.trusted = append(r.trusted, p.Masked())
	}
	return r, nil
}

// Resolve returns the client IP of a request from remoteAddr, its TCP peer (host:port), and xff,
// its X-Forwarded-For headers in order (TDD-07 §1). With no trusted proxies, or a peer that is not
// one, it is the peer. Otherwise the header's entries, then the peer, are walked from the right:
// the client is the first address that is not trusted, or the left-most if every one is. An entry
// that is not an address ends the walk at the trusted hop to its right. It is the zero Addr only
// when remoteAddr is not an address, which only a listener that is not TCP gives.
func (r *Resolver) Resolve(remoteAddr string, xff []string) netip.Addr {
	peer, ok := parsePeer(remoteAddr)
	if !ok {
		return netip.Addr{}
	}
	if !r.isTrusted(peer) {
		return peer
	}
	client := peer
	for i := len(xff) - 1; i >= 0; i-- {
		// Walk the header's entries from the right without splitting it, so a long header costs
		// no allocation and only the entries actually read.
		for rest := xff[i]; rest != ""; {
			var e string
			if k := strings.LastIndexByte(rest, ','); k >= 0 {
				rest, e = rest[:k], rest[k+1:]
			} else {
				rest, e = "", rest
			}
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			a, ok := parseEntry(e)
			if !ok {
				return client
			}
			if !r.isTrusted(a) {
				return a
			}
			client = a
		}
	}
	return client
}

// Middleware keeps the request's client IP in its context, for From.
func (r *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ip := r.Resolve(req.RemoteAddr, req.Header.Values(Header))
		next.ServeHTTP(w, req.WithContext(With(req.Context(), ip)))
	})
}

// From returns the client IP Middleware kept in ctx, or the zero Addr.
func From(ctx context.Context) netip.Addr {
	ip, _ := ctx.Value(ctxKey{}).(netip.Addr)
	return ip
}

// With returns ctx holding ip as the client IP.
func With(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, ctxKey{}, ip)
}

func (r *Resolver) isTrusted(a netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parsePeer parses a TCP peer address, host:port.
func parsePeer(s string) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return normal(ap.Addr()), true
}

// parseEntry parses an X-Forwarded-For entry: an address, optionally bracketed (IPv6) or with a
// port.
func parseEntry(s string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		return normal(a), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return normal(ap.Addr()), true
	}
	if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
		if a, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil && a.Is6() {
			return normal(a), true
		}
	}
	return netip.Addr{}, false
}

// normal drops a zone and reads an IPv4-mapped IPv6 address as IPv4.
func normal(a netip.Addr) netip.Addr {
	return a.WithZone("").Unmap()
}
