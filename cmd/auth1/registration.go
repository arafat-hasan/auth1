package main

import (
	"crypto/rand"
	"log/slog"
	"time"

	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/trace"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/domain/identifier"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/domain/password"
)

// The per-address send limits that are not configuration (TDD-07 L-7): one send in the short
// window (otp.resend_after), and an hour as the long window (otp.max_sends_per_hour in it).
const (
	sendsPerShortWindow = 1
	sendWindowLong      = time.Hour
)

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
	logger   *slog.Logger
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
	challenges, err := app.NewChallenges(flows, outbox, app.NewMessages(p.types), mac, ids, clock, rand.Reader, app.ChallengeRules{
		OTPLength: cfg.OTP.Length, MaxAttempts: cfg.OTP.MaxAttempts, OTPTTL: cfg.OTP.TTL, LinkTTL: cfg.Links.VerificationTTL,
		Windows:  app.SendWindows{Short: cfg.OTP.ResendAfter, Long: sendWindowLong},
		MaxShort: sendsPerShortWindow, MaxLong: cfg.OTP.MaxSendsPerHour, Cooldown: cfg.OTP.Cooldown,
	})
	if err != nil {
		return nil, err
	}
	clients := make(map[string]app.RegistrationClient, len(cfg.Clients))
	for _, c := range cfg.Clients {
		clients[c.ID] = app.RegistrationClient{ID: c.ID, SelfRegistration: c.SelfRegistration}
	}
	return app.NewRegistration(app.RegistrationDeps{
		UnitOfWork: postgres.NewUnitOfWork(p.db, cfg.Database.AcquireTimeout, p.tracing),
		Accounts:   postgres.NewAccounts(p.db, fc, bidx), Flows: flows, Challenges: challenges, Outbox: outbox,
		Audit: postgres.NewAudit(p.db), Hasher: p.hasher, Registry: p.registry, Limits: p.limits,
		IDs: ids, Clock: clock, Rand: rand.Reader, MAC: mac, Logger: p.logger,
	}, app.RegistrationOptions{
		Clients: clients, Locales: cfg.Locales.Allowed, FlowTTL: cfg.Flows.PendingRegistrationTTL, Password: p.policy,
	})
}
