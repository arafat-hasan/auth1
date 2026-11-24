package caller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"

	"go.opentelemetry.io/otel/metric"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/problem"
)

// Mode is which credentials service operations accept (service_auth.mode).
type Mode int

// The modes.
const (
	// ModeNone accepts none: service_auth.mode is not configured, which only development allows.
	ModeNone Mode = iota
	// ModeMesh accepts the workload identity.
	ModeMesh
	// ModeClientCredentials accepts a service token, through Options.Tokens.
	ModeClientCredentials
	// ModeBoth accepts either, the workload identity first.
	ModeBoth
)

// TokenVerifier validates a client-credentials token (TDD-05 §2), returning its client as a
// Caller of KindClient with the token's scopes. Any error, another Kind or an empty ID means no
// caller. Only Kind, ID and a copy of Scopes are kept; Actor comes from the request. serve fills
// it with tokens.Validator.ValidateService.
type TokenVerifier interface {
	VerifyServiceToken(ctx context.Context, token string) (Caller, error)
}

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
	Mode   Mode
	Source Source
	// Header is the identity header's name, for SourceHeader.
	Header string
	Format Format
	// TrustedSidecars are the CIDRs of service_auth.mesh.trusted_sidecar_cidrs: the identity
	// header counts only when the TCP peer is in one of them.
	TrustedSidecars []string
	// Callers maps each configured workload identity to its scopes (service_auth.callers).
	Callers map[string][]string
	// Tokens accepts service tokens; nil accepts none.
	Tokens TokenVerifier
	// BasePath is http.base_path, under which the operations are mounted.
	BasePath string
	// Match finds a request's operation; nil uses gen.Match(BasePath).
	Match func(*http.Request) (id string, op gen.Operation, ok bool)
	// Problems writes the refusals.
	Problems *problem.Writer
	// Audit records each denial, outside any transaction.
	Audit app.AuditWriter
	// Denied is auth1_service_calls_denied_total.
	Denied metric.Int64Counter
	Logger *slog.Logger
}

// Resolver resolves service callers. Build it with New.
type Resolver struct {
	o        Options
	sidecars []netip.Prefix
}

// New returns the resolver for o. It refuses missing dependencies (Problems, Audit, Denied,
// Logger), a mode that reads the mesh header with no header name, and a trusted sidecar that is
// not a CIDR or that is an IPv4-mapped range wider than the IPv4 space. It keeps its own copy of
// Callers.
func New(o Options) (*Resolver, error) {
	for name, missing := range map[string]bool{
		"Problems": o.Problems == nil, "Audit": o.Audit == nil, "Denied": o.Denied == nil, "Logger": o.Logger == nil,
	} {
		if missing {
			return nil, fmt.Errorf("caller: Options.%s is required", name)
		}
	}
	if (o.Mode == ModeMesh || o.Mode == ModeBoth) && o.Source == SourceHeader && o.Header == "" {
		return nil, errors.New("caller: the mesh identity header has no name")
	}
	if o.Match == nil {
		o.Match = gen.Match(o.BasePath)
	}
	callers := make(map[string][]string, len(o.Callers))
	for id, scopes := range o.Callers {
		callers[id] = slices.Clone(scopes)
	}
	o.Callers = callers
	r := &Resolver{o: o}
	for _, s := range o.TrustedSidecars {
		p, err := sidecarPrefix(s)
		if err != nil {
			return nil, err
		}
		r.sidecars = append(r.sidecars, p)
	}
	return r, nil
}

// sidecarPrefix parses a trusted sidecar CIDR. An IPv4-mapped range becomes the IPv4 range it
// names, since peers are compared unmapped.
func sidecarPrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("caller: trusted sidecar %q is not a CIDR: %w", s, err)
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("caller: trusted sidecar %q is wider than the IPv4-mapped range", s)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
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
