package caller

import (
	"fmt"
	"net/http"
	"net/netip"
)

// Source is where a workload identity comes from (service_auth.mesh.source).
type Source int

// The identity sources.
const (
	// SourceHeader takes it from a header set by the local sidecar.
	SourceHeader Source = iota
	// SourcePeerCert takes it from the verified client certificate, when auth1 terminates mTLS.
	SourcePeerCert
)

// Format is how the identity header is read (service_auth.mesh.format).
type Format int

// The header formats.
const (
	// FormatXFCC reads the URI of X-Forwarded-Client-Cert's only element.
	FormatXFCC Format = iota
	// FormatPlain reads the whole header value.
	FormatPlain
)

// Options configure a Resolver.
type Options struct {
	Source Source
	// Header is the identity header's name, for SourceHeader.
	Header string
	Format Format
	// TrustedSidecars are the CIDRs of service_auth.mesh.trusted_sidecar_cidrs: the identity
	// header counts only when the TCP peer is in one of them.
	TrustedSidecars []string
}

// Resolver resolves service callers. Build it with New.
type Resolver struct {
	o        Options
	sidecars []netip.Prefix
}

// New returns the resolver for o, or an error for a trusted sidecar that is not a CIDR.
func New(o Options) (*Resolver, error) {
	r := &Resolver{o: o}
	for _, s := range o.TrustedSidecars {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("caller: trusted sidecar %q is not a CIDR: %w", s, err)
		}
		r.sidecars = append(r.sidecars, p.Masked())
	}
	return r, nil
}

// workloadIdentity returns the request's workload identity (TDD-05 §1). A request that fails the
// trust rule has none: its identity headers are ignored, not an error.
func (r *Resolver) workloadIdentity(req *http.Request) (string, bool) {
	if r.o.Source == SourcePeerCert {
		if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 || len(req.TLS.VerifiedChains[0]) == 0 {
			return "", false
		}
		uris := req.TLS.VerifiedChains[0][0].URIs
		if len(uris) == 0 || uris[0].String() == "" {
			return "", false
		}
		return uris[0].String(), true
	}
	if !r.fromSidecar(req.RemoteAddr) {
		return "", false
	}
	values := req.Header.Values(r.o.Header)
	if r.o.Format == FormatXFCC {
		return xfccURI(values)
	}
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

// fromSidecar reports whether the TCP peer remoteAddr is in a trusted sidecar CIDR.
func (r *Resolver) fromSidecar(remoteAddr string) bool {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return false
	}
	a := ap.Addr().Unmap()
	for _, p := range r.sidecars {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
