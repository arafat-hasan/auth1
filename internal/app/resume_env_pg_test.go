package app_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/identifier"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/domain/password"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// resumeEnv is registration on a migrated database, as auth1_app, with an email verified by code
// (or link, newResumeEnvLink), the defaults of the challenge rules and L-11 at 10 an hour.
type resumeEnv struct {
	reg     *app.Registration
	su      *bun.DB
	fc      *crypto.FieldCrypto
	flows   *postgres.Flows
	limiter *fakes.RateLimiter
	deps    app.RegistrationDeps
	opts    app.RegistrationOptions
}

// pgHasher hashes to "phc:<password>", so registrations need no Argon2id.
type pgHasher struct{ app.PasswordHasher }

func (pgHasher) Hash(_ context.Context, pw []byte) (string, string, error) {
	return "phc:" + string(pw), "1", nil
}

var resumeIP = netip.MustParseAddr("198.51.100.7")

func newResumeEnv(t *testing.T) *resumeEnv {
	t.Helper()
	return newResumeEnvWith(t, flow.MethodEmailCode)
}

func newResumeEnvWith(t *testing.T, verify flow.Method) *resumeEnv {
	t.Helper()
	dsn := pgtest.DSN(t)
	db := openDB(t, pgtest.As(t, dsn, pgtest.App))
	ring, err := crypto.ParseKeyring(
		fmt.Appendf(nil, "keys:\n  - {id: 1, key: %q, state: active}\n", randomKey(t)), crypto.StateDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	key := func() crypto.Key {
		k, err := crypto.ParseKey([]byte(randomKey(t)))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	bidx, err := crypto.NewBlindIndex(key())
	if err != nil {
		t.Fatal(err)
	}
	mac, err := crypto.NewMAC(key())
	if err != nil {
		t.Fatal(err)
	}
	fc := crypto.NewFieldCrypto(ring)
	types, errs := message.NewTypes(nil)
	if errs != nil {
		t.Fatal(errs)
	}
	registry, err := identifier.NewRegistry(identifier.Builtin(), map[string]identifier.Policy{
		"email": {Required: true, Verify: verify, SignIn: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &resumeEnv{su: openDB(t, dsn), fc: fc, flows: postgres.NewFlows(db, fc, bidx), limiter: fakes.NewRateLimiter()}
	rules := map[app.Rule]app.RateLimit{}
	for _, r := range app.Rules() {
		rules[r] = app.RateLimit{Limit: 1000, Window: time.Hour}
	}
	limits, err := app.NewRateLimits(e.limiter, rules)
	if err != nil {
		t.Fatal(err)
	}
	ids, clock := system.UUIDv7{}, system.Clock{}
	outbox := postgres.NewOutbox(db, ids)
	ch, err := app.NewChallenges(e.flows, outbox, app.NewMessages(types), mac, ids, clock, rand.Reader, challengeRules)
	if err != nil {
		t.Fatal(err)
	}
	e.deps = app.RegistrationDeps{
		UnitOfWork: postgres.NewUnitOfWork(db, 5*time.Second, noop.NewTracerProvider()),
		Accounts:   postgres.NewAccounts(db, fc, bidx), Flows: e.flows, Challenges: ch, Outbox: outbox,
		Audit: postgres.NewAudit(db), Hasher: pgHasher{}, Registry: registry, Limits: limits,
		IDs: ids, Clock: clock, Rand: rand.Reader, MAC: mac, Logger: slog.New(slog.DiscardHandler),
	}
	e.opts = app.RegistrationOptions{
		Clients:     map[string]app.RegistrationClient{"web": {ID: "web", SelfRegistration: true}, "console": {ID: "console"}},
		Locales:     []string{"en-GB"},
		FlowTTL:     24 * time.Hour,
		Password:    password.Policy{MinLength: 12, MaxLength: 128},
		FactorLimit: account.FactorLimit{Limit: 10, Window: time.Hour},
	}
	if e.reg, err = app.NewRegistration(e.deps, e.opts); err != nil {
		t.Fatal(err)
	}
	return e
}

// register starts a registration with email and moves every send to the address two hours back,
// so the send limits leave room for what the test does next.
func (e *resumeEnv) register(t *testing.T, email string) app.RegistrationStarted {
	t.Helper()
	s, err := e.reg.Start(t.Context(), app.StartRegistration{
		ClientID: "web", DisplayName: "Someone", Locale: "en-GB", Identifiers: map[string]string{"email": email},
		Password: flow.Secret("correct horse battery staple"), IP: resumeIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.age(t, 2*time.Hour)
	return s
}

// age moves every send back by d.
func (e *resumeEnv) age(t *testing.T, d time.Duration) {
	t.Helper()
	e.exec(t, "UPDATE challenge_sends SET sent_at = sent_at - make_interval(secs => ?)", d.Seconds())
	e.exec(t, "UPDATE challenges SET last_sent_at = last_sent_at - make_interval(secs => ?) WHERE last_sent_at IS NOT NULL", d.Seconds())
}

func (e *resumeEnv) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := e.su.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}

// resumeRow is a resume challenge as stored.
type resumeRow struct {
	ID       uuid.UUID
	FlowID   uuid.UUID
	Sends    int
	Attempts int
	Open     bool
	Consumed bool
	Secret   []byte // sealed; nil once closed (I-5)
}

// resumes returns the resume challenges of the flows, oldest first.
func (e *resumeEnv) resumes(t *testing.T) []resumeRow {
	t.Helper()
	rows, err := e.su.QueryContext(t.Context(), `
		SELECT id, flow_id, sends, attempts, closed_at IS NULL, consumed_at IS NOT NULL, secret
		FROM challenges WHERE purpose = 'resume' ORDER BY created_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []resumeRow
	for rows.Next() {
		var r resumeRow
		if err := rows.Scan(&r.ID, &r.FlowID, &r.Sends, &r.Attempts, &r.Open, &r.Consumed, &r.Secret); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// code returns the open challenge's code, decrypted, as the resolver would.
func (e *resumeEnv) code(t *testing.T, id uuid.UUID) flow.Secret {
	t.Helper()
	var sealed []byte
	if err := e.su.QueryRowContext(t.Context(), "SELECT secret FROM challenges WHERE id = ?", id).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	plain, err := e.fc.Open(app.NewPlace("challenges", "secret", id), sealed)
	if err != nil {
		t.Fatal(err)
	}
	return flow.Secret(plain)
}

// delivery is a delivery row's body, as the relay reads it.
type delivery struct {
	Subject   uuid.UUID
	RequestID string         `json:"request_id"`
	Type      string         `json:"type"`
	Variables map[string]any `json:"variables"`
}

// deliveries returns the delivery rows of type typ, oldest first.
func (e *resumeEnv) deliveries(t *testing.T, typ string) []delivery {
	t.Helper()
	rows, err := e.su.QueryContext(t.Context(),
		"SELECT subject, body FROM outbox WHERE destination = 'delivery' AND type = ? ORDER BY created_at, id", typ)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []delivery
	for rows.Next() {
		var (
			d    delivery
			body []byte
		)
		if err := rows.Scan(&d.Subject, &body); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// auditRow is an audit entry of action.
type auditRow struct {
	AccountID *uuid.UUID
	Outcome   string
	Details   map[string]any
}

func (e *resumeEnv) audits(t *testing.T, action string) []auditRow {
	t.Helper()
	rows, err := e.su.QueryContext(t.Context(),
		"SELECT account_id, outcome, details FROM auth_audit WHERE action = ? ORDER BY id", action)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []auditRow
	for rows.Next() {
		var (
			r       auditRow
			details []byte
		)
		if err := rows.Scan(&r.AccountID, &r.Outcome, &details); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(details, &r.Details); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}
