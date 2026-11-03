package caller

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"

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
// Caller of KindClient with the token's scopes. Any error means no caller. WP-70 implements it.
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

// New returns the resolver for o, or an error for a trusted sidecar that is not a CIDR.
func New(o Options) (*Resolver, error) {
	if o.Match == nil {
		o.Match = gen.Match(o.BasePath)
	}
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
