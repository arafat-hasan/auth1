package main

import (
	"crypto/rand"
	"slices"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// knownDeviceWindow is how long after its last session ended a device keeps its own throttle
// bucket (TDD-07 §4).
const knownDeviceWindow = 90 * 24 * time.Hour

// newSignIn builds the password sign-in and its completion (TDD-02 §5.1, §5.3) on PostgreSQL,
// from the parts registration is built from and the token signer.
func newSignIn(p registrationParts, signer app.TokenSigner) (*app.SignIn, error) {
	cfg := p.cfg
	fc := crypto.NewFieldCrypto(p.keys.fields)
	bidx, err := crypto.NewBlindIndex(p.keys.blindIndex)
	if err != nil {
		return nil, err
	}
	dmac, err := crypto.NewDeviceMAC(p.keys.device)
	if err != nil {
		return nil, err
	}
	ids, clock := system.UUIDv7{}, system.Clock{}
	devices, err := app.NewDeviceCookies(dmac, clock, ids)
	if err != nil {
		return nil, err
	}
	issuer, err := tokens.NewIssuer(tokens.Config{
		Issuer: cfg.HTTP.Issuer, SelfAudience: cfg.Tokens.SelfAudience, AccessTTL: cfg.Tokens.AccessTTL,
	}, signer, clock, ids)
	if err != nil {
		return nil, err
	}
	accounts := postgres.NewAccounts(p.db, fc, bidx)
	notices := app.NewNotices(accounts, postgres.NewOutbox(p.db, ids), app.NewMessages(p.types), p.registry, clock,
		app.NoticeOptions{RetiredAddressWindow: cfg.Delivery.RetiredAddressWindow, NewSignIn: cfg.Delivery.Notices.NewSignIn})
	clients := make(map[string]app.SignInClient, len(cfg.Clients))
	for _, c := range cfg.Clients {
		clients[c.ID] = app.SignInClient{
			ID: c.ID, Audience: c.Audience, AllowedRoles: c.AllowedRoles,
			Password:      slices.Contains(c.FirstFactors, config.FactorPassword),
			MFARequired:   c.MFA == config.MFARequired,
			BodyTransport: c.RefreshTransport == config.RefreshBody,
		}
	}
	f := cfg.RateLimits.SignInFailures
	return app.NewSignIn(app.SignInDeps{
		UnitOfWork: postgres.NewUnitOfWork(p.db, cfg.Database.AcquireTimeout, p.tracing),
		Accounts:   accounts, Flows: postgres.NewFlows(p.db, fc, bidx), Sessions: postgres.NewSessions(p.db, fc),
		Throttles: postgres.NewSignInThrottles(p.db), Notices: notices, Audit: postgres.NewAudit(p.db),
		Hasher: p.hasher, Registry: p.registry, Limits: p.limits, Access: issuer, Devices: devices,
		IDs: ids, Clock: clock, Rand: rand.Reader, Logger: p.logger,
	}, app.SignInOptions{
		Clients: clients, FlowTTL: cfg.MFA.SignInFlowTTL, IdleTTL: cfg.Tokens.RefreshIdleTTL,
		AbsoluteTTL: cfg.Tokens.RefreshAbsoluteTTL, KnownDeviceWindow: knownDeviceWindow,
		RestrictedSignIn: cfg.Statuses.RestrictedSignIn,
		Throttle:         account.ThrottlePolicy{Threshold: f.Threshold, FirstDelay: f.FirstDelay, MaxDelay: f.MaxDelay},
	})
}
