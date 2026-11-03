package main

import (
	"crypto/rand"
	"time"

	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/trace"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/identifier"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/domain/password"
)

// sendWindowLong is the long window of the per-address send limits (TDD-07 L-7): an hour.
const sendWindowLong = time.Hour

// registrationParts are what the registration flow is built from: the configuration, the pool
// and keys, and the components start-up has already built.
type registrationParts struct {
	cfg      *config.Config
	db       *bun.DB
	keys     *cryptoKeys
	registry *identifier.Registry
	types    *message.Types
	policy   password.Policy
	hasher   app.PasswordHasher
	limits   *app.RateLimits
	tracing  trace.TracerProvider
}

// newRegistration builds the registration flow (TDD-02 §3) on PostgreSQL.
func newRegistration(p registrationParts) (*app.Registration, error) {
	cfg := p.cfg
	fc := crypto.NewFieldCrypto(p.keys.fields)
	bidx, err := crypto.NewBlindIndex(p.keys.blindIndex)
	if err != nil {
		return nil, err
	}
	mac, err := crypto.NewMAC(p.keys.mac)
	if err != nil {
		return nil, err
	}
	ids, clock := system.UUIDv7{}, system.Clock{}
	flows := postgres.NewFlows(p.db, fc, bidx)
	outbox := postgres.NewOutbox(p.db, ids)
	challenges := app.NewChallenges(flows, outbox, app.NewMessages(p.types), mac, ids, clock, rand.Reader, app.ChallengeRules{
		OTPLength: cfg.OTP.Length, MaxAttempts: cfg.OTP.MaxAttempts, OTPTTL: cfg.OTP.TTL, LinkTTL: cfg.Links.VerificationTTL,
		Windows:  app.SendWindows{Short: cfg.OTP.ResendAfter, Long: sendWindowLong},
		MaxShort: 1, MaxLong: cfg.OTP.MaxSendsPerHour,
	})
	clients := make(map[string]app.RegistrationClient, len(cfg.Clients))
	for _, c := range cfg.Clients {
		clients[c.ID] = app.RegistrationClient{ID: c.ID, SelfRegistration: c.SelfRegistration}
	}
	return app.NewRegistration(app.RegistrationDeps{
		UnitOfWork: postgres.NewUnitOfWork(p.db, cfg.Database.AcquireTimeout, p.tracing),
		Accounts:   postgres.NewAccounts(p.db, fc, bidx), Flows: flows, Challenges: challenges, Outbox: outbox,
		Audit: postgres.NewAudit(p.db), Hasher: p.hasher, Registry: p.registry, Limits: p.limits,
		IDs: ids, Clock: clock, Rand: rand.Reader, MAC: mac,
	}, app.RegistrationOptions{
		Clients: clients, Locales: cfg.Locales.Allowed, FlowTTL: cfg.Flows.PendingRegistrationTTL,
		Password: p.policy, Resend: flow.ResendRules{ResendAfter: cfg.OTP.ResendAfter, Cooldown: cfg.OTP.Cooldown},
	}), nil
}
