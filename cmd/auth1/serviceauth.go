package main

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/http/middleware/caller"
)

// loadServiceAuth maps service_auth onto the caller middleware's options (TDD-05 §1, §3), less
// the dependencies serve adds. A trusted sidecar that is not a CIDR is a problem, so config check
// and serve refuse it.
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
	for _, c := range sa.Callers {
		o.Callers[c.Identity] = c.Scopes
	}
	var problems []*config.Problem
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
// (TDD-05 §1): any peer in it may name its own workload identity. cidrs have passed
// loadServiceAuth.
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
