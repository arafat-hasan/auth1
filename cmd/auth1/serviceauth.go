package main

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/http/middleware/caller"
)

// loadServiceAuth maps service_auth onto the caller middleware's options (TDD-05 §1, §3), less
// the dependencies serve adds. config check and serve refuse what it reports as problems: a
// trusted sidecar that is not a CIDR, an empty or repeated caller identity, and no header name
// when the mesh identity comes from a header.
func loadServiceAuth(cfg *config.Config) (caller.Options, []*config.Problem) {
	sa := cfg.ServiceAuth
	o := caller.Options{
		Header:          sa.Mesh.Header,
		TrustedSidecars: sa.Mesh.TrustedSidecarCIDRs,
		BasePath:        cfg.HTTP.BasePath,
		Callers:         make(map[string][]string, len(sa.Callers)),
	}
	switch sa.Mode {
	case config.ServiceAuthMesh:
		o.Mode = caller.ModeMesh
	case config.ServiceAuthClientCredentials:
		o.Mode = caller.ModeClientCredentials
	case config.ServiceAuthBoth:
		o.Mode = caller.ModeBoth
	}
	if sa.Mesh.Source == config.MeshSourcePeerCert {
		o.Source = caller.SourcePeerCert
	}
	if sa.Mesh.Format == config.MeshFormatPlain {
		o.Format = caller.FormatPlain
	}
	var problems []*config.Problem
	if (o.Mode == caller.ModeMesh || o.Mode == caller.ModeBoth) && o.Source == caller.SourceHeader && o.Header == "" {
		problems = append(problems, &config.Problem{Path: "service_auth.mesh.header", Message: "required with source header"})
	}
	for i, c := range sa.Callers {
		path := fmt.Sprintf("service_auth.callers[%d].identity", i)
		if _, dup := o.Callers[c.Identity]; dup {
			problems = append(problems, &config.Problem{Path: path, Message: "repeats an earlier caller"})
			continue
		}
		if c.Identity == "" {
			problems = append(problems, &config.Problem{Path: path, Message: "required"})
			continue
		}
		o.Callers[c.Identity] = c.Scopes
	}
	for i, s := range sa.Mesh.TrustedSidecarCIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			problems = append(problems, &config.Problem{
				Path:    fmt.Sprintf("service_auth.mesh.trusted_sidecar_cidrs[%d]", i),
				Message: fmt.Sprintf("%q is not a CIDR, e.g. 127.0.0.1/32", s),
			})
		}
	}
	return o, problems
}

// warnSidecars logs a warning for each trusted sidecar range that reaches beyond loopback
// (TDD-05 §1): any peer in it may name its own workload identity. It skips an entry that does not
// parse, which loadServiceAuth has already refused.
func warnSidecars(logger *slog.Logger, cidrs []string) {
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		p = p.Masked()
		loopback := p.Addr().IsLoopback() && ((p.Addr().Is4() && p.Bits() >= 8) || p.Bits() == 128)
		if !loopback {
			logger.Warn("trusted sidecar range is not loopback: any peer in it can name its own workload identity",
				slog.String("cidr", s))
		}
	}
}

// warnServiceAuth logs a warning for each credential o's mode accepts that no request can present
// yet, so that the 401s it causes are explained at start-up: service tokens without a verifier
// (WP-70), and a peer certificate, since nothing in auth1 terminates TLS.
func warnServiceAuth(logger *slog.Logger, o caller.Options) {
	if (o.Mode == caller.ModeClientCredentials || o.Mode == caller.ModeBoth) && o.Tokens == nil {
		logger.Warn("service tokens are not accepted yet: every call that relies on one answers 401")
	}
	if (o.Mode == caller.ModeMesh || o.Mode == caller.ModeBoth) && o.Source == caller.SourcePeerCert {
		logger.Warn("service_auth.mesh.source peer_cert finds no identity: auth1 does not terminate TLS")
	}
}
