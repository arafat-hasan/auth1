package app_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// expiryEnv is a migrated database with the repositories the expiry job uses, as auth1_app, and
// the superuser's pool for seeding and reading.
type expiryEnv struct {
	su       *bun.DB
	uow      *postgres.UnitOfWork
	accounts *postgres.Accounts
	flows    *postgres.Flows
	outbox   *postgres.Outbox
	audit    *postgres.Audit
	n        int
}

// openDB opens a pool on dsn, closed when the test ends.
func openDB(t *testing.T, dsn string) *bun.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(path, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := postgres.Open(config.Database{DSNFile: config.NewSecretFile(path), MaxConns: 10}, config.EnvDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// randomKey is the base64 of 32 random bytes.
func randomKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, crypto.KeySize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func newExpiryEnv(t *testing.T) *expiryEnv {
	t.Helper()
	dsn := pgtest.DSN(t)
	db := openDB(t, pgtest.As(t, dsn, pgtest.App))
	ring, err := crypto.ParseKeyring(
		fmt.Appendf(nil, "keys:\n  - {id: 1, key: %q, state: active}\n", randomKey(t)), crypto.StateDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.ParseKey([]byte(randomKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	bidx, err := crypto.NewBlindIndex(key)
	if err != nil {
		t.Fatal(err)
	}
	fc := crypto.NewFieldCrypto(ring)
	return &expiryEnv{
		su:       openDB(t, dsn),
		uow:      postgres.NewUnitOfWork(db, 5*time.Second, noop.NewTracerProvider()),
		accounts: postgres.NewAccounts(db, fc, bidx),
		flows:    postgres.NewFlows(db, fc, bidx),
		outbox:   postgres.NewOutbox(db, system.UUIDv7{}),
		audit:    postgres.NewAudit(db),
	}
}

// deps are the expiry's dependencies on the environment.
func (e *expiryEnv) deps() app.FlowExpiryDeps {
	return app.FlowExpiryDeps{
		UnitOfWork: e.uow, Accounts: e.accounts, Flows: e.flows, Expiring: e.flows,
		Outbox: e.outbox, Audit: e.audit, Logger: slog.New(slog.DiscardHandler),
	}
}

func (e *expiryEnv) expiry(t *testing.T, batch int) *app.FlowExpiry {
	t.Helper()
	x, err := app.NewFlowExpiry(e.deps(), batch)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func (e *expiryEnv) do(t *testing.T, fn func(ctx context.Context) error) {
	t.Helper()
	if err := e.uow.Do(t.Context(), fn); err != nil {
		t.Fatal(err)
	}
}

func (e *expiryEnv) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := e.su.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func (e *expiryEnv) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := e.su.QueryRowContext(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// seeded is an account with an open flow and one open challenge.
type seeded struct {
	account   uuid.UUID
	flow      uuid.UUID
	emailID   uuid.UUID
	phoneID   uuid.UUID
	challenge uuid.UUID
}

// seed creates a pending account registered via "web" with a verified email and an unverified
// phone, and opens a flow of kind with a verify_identifier challenge on the phone; with ago > 0
// both expired ago seconds back.
func (e *expiryEnv) seed(t *testing.T, kind flow.Kind, ago int) seeded {
	t.Helper()
	e.n++
	s := seeded{account: uuid.New(), flow: uuid.New(), emailID: uuid.New(), phoneID: uuid.New(), challenge: uuid.New()}
	a := account.NewAccount{
		ID: s.account, DisplayName: "Ada", Locale: "en-GB", RegisteredVia: "web",
		Password: account.PasswordCredential{Hash: "$argon2id$v=19$m=65536,t=2,p=1$c2FsdA$aGFzaA", PepperKID: "1"},
		Identifiers: []account.NewIdentifier{
			{ID: s.emailID, Type: "email", Value: fmt.Sprintf("person%d@example.org", e.n), Verified: true},
			{ID: s.phoneID, Type: "phone", Value: fmt.Sprintf("+4479460%05d", e.n)},
		},
	}
	states := map[flow.Kind]flow.State{
		flow.KindRegistration: flow.RegistrationState{PendingTypes: []string{"phone"}},
		flow.KindInvitation:   flow.InvitationState{Roles: []string{"member"}, Accepted: true, PendingTypes: []string{"phone"}},
		flow.KindSignIn:       flow.SignInState{FirstFactor: flow.FirstFactorPassword, Step: flow.StepSecondFactor},
	}
	handle := crypto.SHA256([]byte(s.flow.String()))
	f := flow.NewFlow{ID: s.flow, Kind: kind, AccountID: s.account, ClientID: "web", HandleHash: handle,
		State: states[kind], ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)}
	e.do(t, func(ctx context.Context) error {
		if err := e.accounts.Create(ctx, a); err != nil {
			return err
		}
		if _, err := e.accounts.GetForUpdate(ctx, s.account); err != nil {
			return err
		}
		if err := e.flows.Open(ctx, f); err != nil {
			return err
		}
		return e.flows.OpenChallenge(ctx, flow.NewChallengeRecord{
			ID: s.challenge, FlowID: s.flow, Purpose: flow.PurposeVerifyIdentifier, Method: flow.MethodSMSOTP,
			IdentifierID: &s.phoneID, TargetType: "phone", TargetValue: a.Identifiers[1].Value,
			SecretMAC: crypto.SHA256([]byte("otp")), Secret: flow.Secret("123456"), MaxAttempts: 3,
			ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
		})
	})
	if ago > 0 {
		e.exec(t, "UPDATE flows SET expires_at = now() - make_interval(secs => ?) WHERE id = ?", ago, s.flow)
		e.exec(t, "UPDATE challenges SET expires_at = now() - make_interval(secs => ?) WHERE flow_id = ?", ago, s.flow)
	}
	return s
}

// state reads the account's status, status_reason, registered_via and version.
func (e *expiryEnv) state(t *testing.T, id uuid.UUID) (status, reason, via string, version int64) {
	t.Helper()
	err := e.su.QueryRowContext(t.Context(),
		"SELECT status, coalesce(status_reason, ''), registered_via, version FROM accounts WHERE id = ?", id).
		Scan(&status, &reason, &via, &version)
	if err != nil {
		t.Fatal(err)
	}
	return status, reason, via, version
}

func (e *expiryEnv) currentIdentifiers(t *testing.T, id uuid.UUID) int {
	t.Helper()
	return e.count(t, "SELECT count(*) FROM identifiers WHERE account_id = ? AND retired_at IS NULL", id)
}

func (e *expiryEnv) flowReason(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var r string
	if err := e.su.QueryRowContext(t.Context(), "SELECT coalesce(close_reason, '') FROM flows WHERE id = ?", id).Scan(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *expiryEnv) events(t *testing.T, id uuid.UUID) int {
	t.Helper()
	return e.count(t, "SELECT count(*) FROM outbox WHERE destination = 'event' AND subject = ?", id)
}

// TestFlowExpiryReleasesPendingAccount checks TDD-02 §2.5 step 1 on one abandoned registration:
// I-12 (no current identifier) and I-5 (no secret in a closed challenge), the event and the audit.
func TestFlowExpiryReleasesPendingAccount(t *testing.T) {
	t.Parallel()
	e := newExpiryEnv(t)
	s := e.seed(t, flow.KindRegistration, 60)
	_, _, _, before := e.state(t, s.account)

	if err := e.expiry(t, 0).Run(t.Context()); err != nil {
		t.Fatal(err)
	}

	if n := e.currentIdentifiers(t, s.account); n != 0 {
		t.Errorf("I-12: %d current identifiers, want 0", n)
	}
	status, reason, via, after := e.state(t, s.account)
	if status != "deleted" || reason != "" || via != "web" || after != before+1 {
		t.Errorf("account: status %q, reason %q, via %q, version %d; want deleted, none, web, %d",
			status, reason, via, after, before+1)
	}
	if r := e.flowReason(t, s.flow); r != "expired" {
		t.Errorf("flow close reason %q, want expired", r)
	}
	if n := e.count(t, "SELECT count(*) FROM challenges WHERE flow_id = ? AND (closed_at IS NULL OR secret IS NOT NULL)", s.flow); n != 0 {
		t.Errorf("I-5: %d challenges open or holding a secret", n)
	}

	var typ string
	var body []byte
	var version int64
	if err := e.su.QueryRowContext(t.Context(),
		"SELECT type, body, account_version FROM outbox WHERE destination = 'event' AND subject = ?", s.account).
		Scan(&typ, &body, &version); err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"account_id": s.account.String(), "client_id": "web",
		"actor": map[string]any{"kind": "system", "id": "flow-expiry"},
	}
	if typ != "account.registration_expired" || version != after {
		t.Errorf("event type %q at version %d, want account.registration_expired at %d", typ, version, after)
	}
	if diff := cmp.Diff(want, data); diff != "" {
		t.Errorf("event data (-want +got):\n%s", diff)
	}

	var actorKind, actorID, outcome, clientID string
	var details []byte
	if err := e.su.QueryRowContext(t.Context(), `
		SELECT actor_kind, actor_id, outcome, client_id, details FROM auth_audit
		WHERE account_id = ? AND action = 'registration.expire'`, s.account).
		Scan(&actorKind, &actorID, &outcome, &clientID, &details); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	var d map[string]any
	if err := json.Unmarshal(details, &d); err != nil {
		t.Fatal(err)
	}
	if actorKind != "system" || actorID != "flow-expiry" || outcome != "success" || clientID != "web" ||
		d["flow_id"] != s.flow.String() || d["kind"] != "registration" {
		t.Errorf("audit: %s %s %s %s %v", actorKind, actorID, outcome, clientID, d)
	}
}

func TestFlowExpiryLeavesLive(t *testing.T) {
	t.Parallel()
	e := newExpiryEnv(t)
	s := e.seed(t, flow.KindRegistration, 0)
	_, _, _, before := e.state(t, s.account)
	if err := e.expiry(t, 0).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, _, _, after := e.state(t, s.account)
	if status != "pending" || after != before || e.currentIdentifiers(t, s.account) != 2 ||
		e.flowReason(t, s.flow) != "" || e.events(t, s.account) != 0 {
		t.Errorf("a live registration changed: status %q, version %d → %d", status, before, after)
	}
}

// activating is the expiring flows of the environment, activating every account it returns as
// pending: a registration completed between the select and the lock.
type activating struct {
	app.ExpiringFlows
	e       *expiryEnv
	t       *testing.T
	version map[uuid.UUID]int64 // each account's version once activated
}

func (a activating) ExpiredPending(ctx context.Context, limit int) ([]flow.Flow, error) {
	fs, err := a.ExpiringFlows.ExpiredPending(ctx, limit)
	for _, f := range fs {
		if aerr := a.e.uow.Do(ctx, func(ctx context.Context) error {
			if _, err := a.e.accounts.GetForUpdate(ctx, f.AccountID); err != nil {
				return err
			}
			return a.e.accounts.Activate(ctx, f.AccountID)
		}); aerr != nil {
			a.t.Error(aerr)
		}
		var v int64
		if err := a.e.su.QueryRowContext(ctx, "SELECT version FROM accounts WHERE id = ?", f.AccountID).Scan(&v); err != nil {
			a.t.Error(err)
		}
		a.version[f.AccountID] = v
	}
	return fs, err
}

func TestFlowExpiryLeavesActivated(t *testing.T) {
	t.Parallel()
	e := newExpiryEnv(t)
	s := e.seed(t, flow.KindRegistration, 60)
	d := e.deps()
	act := activating{ExpiringFlows: e.flows, e: e, t: t, version: map[uuid.UUID]int64{}}
	d.Expiring = act
	x, err := app.NewFlowExpiry(d, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	status, _, _, version := e.state(t, s.account)
	if status != "active" {
		t.Errorf("status %q, want active", status)
	}
	if version != act.version[s.account] {
		t.Errorf("version %d, want %d: a skipped account rolls back, moving no version", version, act.version[s.account])
	}
	if r := e.flowReason(t, s.flow); r != "expired" {
		t.Errorf("the active account's expired flow: close reason %q, want expired", r)
	}
	if n := e.currentIdentifiers(t, s.account); n != 2 {
		t.Errorf("%d current identifiers, want 2", n)
	}
	if n := e.events(t, s.account); n != 0 {
		t.Errorf("%d events, want 0", n)
	}
}

func TestFlowExpiryDrainsBatches(t *testing.T) {
	t.Parallel()
	e := newExpiryEnv(t)
	var regs, signIns []seeded
	for range 5 {
		regs = append(regs, e.seed(t, flow.KindRegistration, 60))
	}
	for range 3 {
		signIns = append(signIns, e.seed(t, flow.KindSignIn, 60))
	}
	live := e.seed(t, flow.KindSignIn, 0)
	e.exec(t, "UPDATE challenges SET expires_at = now() - interval '1 second' WHERE flow_id = ?", live.flow)

	if err := e.expiry(t, 2).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, s := range regs {
		if status, _, _, _ := e.state(t, s.account); status != "deleted" || e.events(t, s.account) != 1 {
			t.Errorf("registration %v: status %q", s.flow, status)
		}
	}
	for _, s := range signIns {
		// Pending accounts with only a sign-in flow: the flow closes; the account is not expired.
		if r := e.flowReason(t, s.flow); r != "expired" {
			t.Errorf("sign-in flow %v: close reason %q", s.flow, r)
		}
		if status, _, _, _ := e.state(t, s.account); status != "pending" || e.events(t, s.account) != 0 {
			t.Errorf("sign-in account %v: status %q", s.account, status)
		}
	}
	if r := e.flowReason(t, live.flow); r != "" {
		t.Errorf("live flow closed: %q", r)
	}
	if n := e.count(t, "SELECT count(*) FROM challenges WHERE flow_id = ? AND closed_at IS NULL", live.flow); n != 0 {
		t.Errorf("the expired challenge of a live flow is open")
	}
}

// failingOutbox fails every event about one account.
type failingOutbox struct {
	app.OutboxWriter
	mu   sync.Mutex
	fail uuid.UUID
	hits int
}

func (o *failingOutbox) Event(ctx context.Context, typ string, id uuid.UUID, data any) error {
	if id == o.fail {
		o.mu.Lock()
		o.hits++
		o.mu.Unlock()
		return errors.New("outbox down")
	}
	return o.OutboxWriter.Event(ctx, typ, id, data)
}

func TestFlowExpiryFailureSkipped(t *testing.T) {
	t.Parallel()
	e := newExpiryEnv(t)
	bad := e.seed(t, flow.KindRegistration, 120)
	good := e.seed(t, flow.KindRegistration, 60)
	out := &failingOutbox{OutboxWriter: e.outbox, fail: bad.account}
	d := e.deps()
	d.Outbox = out
	x, err := app.NewFlowExpiry(d, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := x.Run(ctx); err == nil {
		t.Fatal("Run succeeded with an account failing")
	}
	if ctx.Err() != nil {
		t.Fatal("Run did not end")
	}
	if status, _, _, _ := e.state(t, bad.account); status != "pending" || e.currentIdentifiers(t, bad.account) != 2 {
		t.Errorf("failed account changed: %q", status)
	}
	if status, _, _, _ := e.state(t, good.account); status != "deleted" {
		t.Errorf("the other account: %q, want deleted", status)
	}
	if out.hits != 1 {
		t.Errorf("failing account tried %d times in one run, want 1", out.hits)
	}
}

func TestNewFlowExpiryRefusesMissing(t *testing.T) {
	t.Parallel()
	_, err := app.NewFlowExpiry(app.FlowExpiryDeps{}, 0)
	if want := "flow expiry: missing UnitOfWork, Accounts, Flows, Expiring, Outbox, Audit"; err == nil || err.Error() != want {
		t.Fatalf("error %v, want %q", err, want)
	}
}

// TestFlowExpiryReleasesInvitedAccount checks TDD-02 §2.5 step 1 for an invitation: I-12, and the
// event's client_id "invitation".
func TestFlowExpiryReleasesInvitedAccount(t *testing.T) {
	t.Parallel()
	e := newExpiryEnv(t)
	s := e.seed(t, flow.KindInvitation, 60)
	e.exec(t, "UPDATE accounts SET registered_via = 'invitation' WHERE id = ?", s.account)
	if err := e.expiry(t, 0).Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.currentIdentifiers(t, s.account); n != 0 {
		t.Errorf("I-12: %d current identifiers, want 0", n)
	}
	if status, _, _, _ := e.state(t, s.account); status != "deleted" {
		t.Errorf("status %q, want deleted", status)
	}
	var client, kind string
	if err := e.su.QueryRowContext(t.Context(), `
		SELECT (SELECT body->>'client_id' FROM outbox WHERE subject = ? AND type = 'account.registration_expired'),
		       (SELECT details->>'kind' FROM auth_audit WHERE account_id = ? AND action = 'registration.expire')`,
		s.account, s.account).Scan(&client, &kind); err != nil {
		t.Fatal(err)
	}
	if client != "invitation" || kind != "invitation" {
		t.Errorf("event client_id %q, audit kind %q; want invitation, invitation", client, kind)
	}
}

func TestFlowExpiryCancelled(t *testing.T) {
	t.Parallel()
	e := newExpiryEnv(t)
	s := e.seed(t, flow.KindRegistration, 60)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.expiry(t, 0).Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled: a cut-short run is no success", err)
	}
	if status, _, _, _ := e.state(t, s.account); status != "pending" {
		t.Errorf("status %q, want pending", status)
	}
}

// unavailableOutbox fails every event with UNAVAILABLE, as the store does in an outage.
type unavailableOutbox struct {
	app.OutboxWriter
	hits atomic.Int64
}

func (o *unavailableOutbox) Event(context.Context, string, uuid.UUID, any) error {
	o.hits.Add(1)
	return &domain.Error{Code: domain.CodeUnavailable, Detail: "The service is temporarily unavailable."}
}

// TestFlowExpiryStopsOnOutage checks that a failure of the store, not of one flow, ends the pass
// at once instead of trying, and logging, every expired flow.
func TestFlowExpiryStopsOnOutage(t *testing.T) {
	t.Parallel()
	e := newExpiryEnv(t)
	for range 4 {
		e.seed(t, flow.KindRegistration, 60)
	}
	out := &unavailableOutbox{OutboxWriter: e.outbox}
	d := e.deps()
	d.Outbox = out
	x, err := app.NewFlowExpiry(d, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Run(t.Context()); err == nil {
		t.Fatal("Run succeeded in an outage")
	}
	if n := out.hits.Load(); n != 1 {
		t.Errorf("tried %d accounts in an outage, want 1", n)
	}
}

// rollbackFailing is the environment's unit of work, failing every rollback.
type rollbackFailing struct{ app.UnitOfWork }

func (u rollbackFailing) Do(ctx context.Context, fn func(context.Context) error) error {
	if err := u.UnitOfWork.Do(ctx, fn); err != nil {
		return errors.Join(err, errors.New("roll back: connection lost"))
	}
	return nil
}

// TestFlowExpirySkipRollbackFailure checks that a rollback failure on a skipped account is
// reported, not taken for a skip.
func TestFlowExpirySkipRollbackFailure(t *testing.T) {
	t.Parallel()
	e := newExpiryEnv(t)
	e.seed(t, flow.KindRegistration, 60)
	d := e.deps()
	d.Expiring = activating{ExpiringFlows: e.flows, e: e, t: t, version: map[uuid.UUID]int64{}}
	d.UnitOfWork = rollbackFailing{e.uow}
	x, err := app.NewFlowExpiry(d, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Run(t.Context()); err == nil {
		t.Fatal("Run succeeded although a rollback failed")
	}
}
