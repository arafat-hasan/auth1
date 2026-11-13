package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/identifier"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/domain/password"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// fakeUoW runs fn and remembers whether a transaction is open; it cannot roll back, so tests check
// errors, not the absence of writes after one.
type fakeUoW struct {
	inTx        bool
	rollbackErr error // joined to fn's error, as a failed rollback is
}

func (u *fakeUoW) Do(ctx context.Context, fn func(context.Context) error) error {
	if u.inTx {
		return fn(ctx)
	}
	u.inTx = true
	defer func() { u.inTx = false }()
	if err := fn(ctx); err != nil && u.rollbackErr != nil {
		return errors.Join(err, u.rollbackErr)
	} else if err != nil {
		return err
	}
	return nil
}

// fakeHasher hashes to "phc:<password>" and fails the test if it hashes inside a transaction (G-4).
type fakeHasher struct {
	app.PasswordHasher
	t      *testing.T
	uow    *fakeUoW
	hashes int
	err    error
}

func (h *fakeHasher) Hash(_ context.Context, pw []byte) (string, string, error) {
	h.hashes++
	if h.uow.inTx {
		h.t.Error("Hash called inside the transaction (G-4)")
	}
	if h.err != nil {
		return "", "", h.err
	}
	return "phc:" + string(pw), "1", nil
}

// regAccounts is the accounts repository of the registration tests: verified values held by
// other accounts, the accounts created and their identifiers.
type regAccounts struct {
	app.Accounts
	clock    *fakes.Clock
	verified map[string]bool // type:value held verified by another account
	created  []account.NewAccount
	accounts map[uuid.UUID]account.Account
	ids      []*account.Identifier
}

func (a *regAccounts) FindVerified(_ context.Context, idType, value string) (account.Identifier, error) {
	if a.verified[idType+":"+value] {
		return account.Identifier{Type: idType, Value: value}, nil
	}
	return account.Identifier{}, &domain.Error{Code: domain.CodeNotFound}
}

func (a *regAccounts) Create(_ context.Context, na account.NewAccount) error {
	a.created = append(a.created, na)
	if a.accounts == nil {
		a.accounts = map[uuid.UUID]account.Account{}
	}
	a.accounts[na.ID] = account.Account{ID: na.ID, Status: account.StatusPending, DisplayName: na.DisplayName,
		Locale: na.Locale, RegisteredVia: na.RegisteredVia, Version: 1}
	for _, ni := range na.Identifiers {
		a.ids = append(a.ids, &account.Identifier{ID: ni.ID, AccountID: na.ID, Type: ni.Type, Value: ni.Value})
	}
	return nil
}

func (a *regAccounts) GetForUpdate(_ context.Context, id uuid.UUID) (account.Account, error) {
	acc, ok := a.accounts[id]
	if !ok {
		return account.Account{}, &domain.Error{Code: domain.CodeNotFound}
	}
	return acc, nil
}

func (a *regAccounts) Identifiers(_ context.Context, accountID uuid.UUID) ([]account.Identifier, error) {
	var out []account.Identifier
	for _, id := range a.ids {
		if id.AccountID == accountID && id.RetiredAt == nil {
			out = append(out, *id)
		}
	}
	slices.SortFunc(out, func(x, y account.Identifier) int { return strings.Compare(x.Type, y.Type) })
	return out, nil
}

func (a *regAccounts) VerifyIdentifier(_ context.Context, id uuid.UUID) error {
	for _, i := range a.ids {
		if i.ID != id || i.VerifiedAt != nil || i.RetiredAt != nil {
			continue
		}
		if a.verified[i.Type+":"+i.Value] {
			return &domain.Error{Code: domain.CodeIdentifierTaken, Detail: "the identifier is taken"}
		}
		t := a.clock.Now()
		i.VerifiedAt = &t
		return nil
	}
	return &domain.Error{Code: domain.CodeNotFound}
}

// regFlows is an in-memory flows repository, on top of sendFlows's records of opened challenges,
// sends and send-limit checks. Its finders see only open flows before their expiry, and answer
// every miss with CHALLENGE_CLOSED, as postgres.Flows does.
type regFlows struct {
	*sendFlows
	findErr       error                       // returned by Find when set
	afterFindLink func(*flow.ChallengeRecord) // run when FindLink has found a challenge
	clock         *fakes.Clock
	flows         []flow.NewFlow
	byID          map[uuid.UUID]*flow.Flow
	chs           []*flow.ChallengeRecord
}

func closedErr() error {
	return &domain.Error{Code: domain.CodeChallengeClosed, Detail: "the challenge is closed"}
}

func (f *regFlows) Open(_ context.Context, nf flow.NewFlow) error {
	f.flows = append(f.flows, nf)
	if f.byID == nil {
		f.byID = map[uuid.UUID]*flow.Flow{}
	}
	f.byID[nf.ID] = &flow.Flow{ID: nf.ID, Kind: nf.Kind, AccountID: nf.AccountID, ClientID: nf.ClientID,
		HandleHash: nf.HandleHash, State: nf.State, ExpiresAt: nf.ExpiresAt, CreatedAt: f.clock.Now()}
	return nil
}

func (f *regFlows) live(id uuid.UUID) (*flow.Flow, bool) {
	fl, ok := f.byID[id]
	return fl, ok && fl.CompletedAt == nil && fl.CancelledAt == nil && fl.ExpiresAt.After(f.clock.Now())
}

func (f *regFlows) Find(_ context.Context, id uuid.UUID, handleHash []byte) (flow.Flow, error) {
	if f.findErr != nil {
		return flow.Flow{}, f.findErr
	}
	fl, ok := f.live(id)
	if !ok || !bytes.Equal(fl.HandleHash, handleHash) {
		return flow.Flow{}, closedErr()
	}
	return *fl, nil
}

func (f *regFlows) LockFlow(ctx context.Context, fl flow.Flow) (flow.Flow, error) {
	return f.Find(ctx, fl.ID, fl.HandleHash)
}

func (f *regFlows) FindLink(_ context.Context, linkHash []byte) (flow.Flow, flow.ChallengeRecord, error) {
	for _, c := range f.chs {
		if c.Method == flow.MethodEmailLink && c.ClosedAt == nil && bytes.Equal(c.SecretMAC, linkHash) {
			if fl, ok := f.live(c.FlowID); ok {
				defer func() {
					if f.afterFindLink != nil {
						f.afterFindLink(c) // what another request does before this one locks
					}
				}()
				return *fl, *c, nil
			}
		}
	}
	return flow.Flow{}, flow.ChallengeRecord{}, closedErr()
}

func (f *regFlows) Update(_ context.Context, id uuid.UUID, state flow.State, attempts int) error {
	f.byID[id].State, f.byID[id].Attempts = state, attempts
	return nil
}

func (f *regFlows) OpenChallenge(ctx context.Context, c flow.NewChallengeRecord) error {
	_ = f.sendFlows.OpenChallenge(ctx, c)
	f.chs = append(f.chs, &flow.ChallengeRecord{ID: c.ID, FlowID: c.FlowID, Purpose: c.Purpose, Method: c.Method,
		IdentifierID: c.IdentifierID, SecretMAC: c.SecretMAC, CreatedAt: f.clock.Now(),
		Challenge: flow.Challenge{MaxAttempts: c.MaxAttempts, ExpiresAt: c.ExpiresAt}})
	return nil
}

func (f *regFlows) challenge(id uuid.UUID) *flow.ChallengeRecord {
	for _, c := range f.chs {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (f *regFlows) LockChallenges(_ context.Context, flowID uuid.UUID) ([]flow.ChallengeRecord, error) {
	var out []flow.ChallengeRecord
	for _, c := range f.chs {
		if c.FlowID == flowID {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (f *regFlows) RecordSend(ctx context.Context, id uuid.UUID) (int, error) {
	c := f.challenge(id)
	if c == nil || c.ClosedAt != nil {
		return 0, &domain.Error{Code: domain.CodeNotFound}
	}
	n, _ := f.sendFlows.RecordSend(ctx, id)
	t := f.clock.Now()
	c.Sends, c.LastSentAt = n, &t
	return n, nil
}

func (f *regFlows) Attempt(_ context.Context, id uuid.UUID) (int, bool, error) {
	c := f.challenge(id)
	if c.ClosedAt != nil || c.Attempts >= c.MaxAttempts {
		return 0, false, nil
	}
	c.Attempts++
	return c.Attempts, true, nil
}

func (f *regFlows) CloseChallenge(_ context.Context, id uuid.UUID, consumed bool) (bool, error) {
	c := f.challenge(id)
	if c.ClosedAt != nil {
		return false, nil
	}
	t := f.clock.Now()
	c.ClosedAt = &t
	if consumed {
		c.ConsumedAt = &t
	}
	return true, nil
}

// eventOutbox records events on top of recordingOutbox's delivery requests.
type eventOutbox struct {
	*recordingOutbox
	events []recordedEvent
}

type recordedEvent struct {
	Type    string
	Account uuid.UUID
	Data    any
}

func (o *eventOutbox) Event(_ context.Context, eventType string, accountID uuid.UUID, data any) error {
	o.events = append(o.events, recordedEvent{eventType, accountID, data})
	return nil
}

// recordingAudit keeps the entries written.
type recordingAudit struct {
	entries []app.AuditEntry
	err     error // returned, writing nothing, when set
}

func (a *recordingAudit) Write(_ context.Context, e app.AuditEntry) error {
	if a.err != nil {
		return a.err
	}
	a.entries = append(a.entries, e)
	return nil
}

type regEnv struct {
	reg      *app.Registration
	uow      *fakeUoW
	accounts *regAccounts
	flows    *regFlows
	outbox   *eventOutbox
	audit    *recordingAudit
	hasher   *fakeHasher
	limiter  *fakes.RateLimiter
	clock    *fakes.Clock
	logs     *syncBuffer
	deps     app.RegistrationDeps
	opts     app.RegistrationOptions
}

const (
	regEmail    = "Someone@Example.com"
	regPhone    = "+44 7400 123456"
	regPassword = "correct horse battery staple"
)

func newRegEnv(t *testing.T) *regEnv {
	t.Helper()
	return newRegEnvEmail(t, emailPol)
}

// newRegEnvEmail is newRegEnv with the email policy email.
func newRegEnvEmail(t *testing.T, email identifier.Policy) *regEnv {
	t.Helper()
	types, errs := message.NewTypes(nil)
	if errs != nil {
		t.Fatal(errs)
	}
	registry, err := identifier.NewRegistry(identifier.Builtin(), map[string]identifier.Policy{
		"email": email, "phone": phonePol,
	})
	if err != nil {
		t.Fatal(err)
	}
	deny, err := password.ParseDenyList(strings.NewReader("password1234\n"))
	if err != nil {
		t.Fatal(err)
	}
	clock := fakes.NewClock(now)
	e := &regEnv{
		uow: &fakeUoW{}, accounts: &regAccounts{clock: clock, verified: map[string]bool{}},
		flows: &regFlows{sendFlows: &sendFlows{}, clock: clock}, outbox: &eventOutbox{recordingOutbox: &recordingOutbox{}},
		audit: &recordingAudit{}, limiter: fakes.NewRateLimiter(), clock: clock,
	}
	e.hasher = &fakeHasher{t: t, uow: e.uow}
	limits, err := app.NewRateLimits(e.limiter, map[app.Rule]app.RateLimit{
		app.RuleGlobalIP: {Limit: 600, Window: time.Minute}, app.RuleSignInIP: {Limit: 30, Window: 5 * time.Minute},
		app.RuleRegistrationIP: {Limit: 5, Window: time.Hour}, app.RuleResetIP: {Limit: 10, Window: time.Hour},
		app.RuleSendIP: {Limit: 20, Window: time.Hour}, app.RuleVerifyIP: {Limit: 30, Window: time.Hour},
		app.RuleResumeIP: {Limit: 10, Window: time.Hour}, app.RuleTokenClient: {Limit: 60, Window: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := fakes.NewIDs()
	rnd := bytes.NewReader(bytes.Repeat([]byte{7}, 1<<16))
	ch, err := app.NewChallenges(e.flows, e.outbox, app.NewMessages(types), testMAC{}, ids, e.clock, rnd, challengeRules)
	if err != nil {
		t.Fatal(err)
	}
	e.logs = &syncBuffer{}
	e.deps = app.RegistrationDeps{
		UnitOfWork: e.uow, Accounts: e.accounts, Flows: e.flows, Challenges: ch, Outbox: e.outbox,
		Audit: e.audit, Hasher: e.hasher, Registry: registry, Limits: limits, IDs: ids, Clock: e.clock,
		Rand: rnd, MAC: testMAC{}, Logger: slog.New(slog.NewTextHandler(e.logs, nil)),
	}
	e.opts = app.RegistrationOptions{
		Clients: map[string]app.RegistrationClient{
			"web": {ID: "web", SelfRegistration: true}, "console": {ID: "console"},
		},
		Locales:     []string{"en", "en-GB"},
		FlowTTL:     24 * time.Hour,
		Password:    password.Policy{MinLength: 12, MaxLength: 128, DenyList: deny},
		FactorLimit: account.FactorLimit{Limit: 10, Window: time.Hour},
	}
	if e.reg, err = app.NewRegistration(e.deps, e.opts); err != nil {
		t.Fatal(err)
	}
	return e
}

// syncBuffer is a bytes.Buffer safe for concurrent writes, for captured logs.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var regIP = netip.MustParseAddr("192.0.2.10")

func startCmd() app.StartRegistration {
	return app.StartRegistration{
		ClientID: "web", DisplayName: "Someone", Locale: "en-GB",
		Identifiers: map[string]string{"email": regEmail, "phone": regPhone},
		Password:    flow.Secret(regPassword), IP: regIP,
	}
}

func TestStartRegistration(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	got, err := e.reg.Start(context.Background(), startCmd())
	if err != nil {
		t.Fatal(err)
	}
	if len(e.accounts.created) != 1 {
		t.Fatalf("created %d accounts; want 1", len(e.accounts.created))
	}
	na := e.accounts.created[0]
	want := account.NewAccount{
		ID: na.ID, DisplayName: "Someone", Locale: "en-GB", RegisteredVia: "web",
		Identifiers: []account.NewIdentifier{
			{ID: na.Identifiers[0].ID, Type: "email", Value: "someone@example.com"},
			{ID: na.Identifiers[1].ID, Type: "phone", Value: "+447400123456"},
		},
		Password: account.PasswordCredential{Hash: "phc:" + regPassword, PepperKID: "1"},
	}
	if diff := cmp.Diff(want, na); diff != "" {
		t.Errorf("account (-want +got):\n%s", diff)
	}
	if len(e.flows.flows) != 1 {
		t.Fatalf("opened %d flows; want 1", len(e.flows.flows))
	}
	nf := e.flows.flows[0]
	if nf.Kind != flow.KindRegistration || nf.AccountID != na.ID || nf.ClientID != "web" ||
		!nf.ExpiresAt.Equal(now.Add(24*time.Hour)) ||
		!cmp.Equal(nf.State, flow.State(flow.RegistrationState{PendingTypes: []string{"email", "phone"}})) {
		t.Errorf("flow = %+v", nf)
	}
	if got.FlowID != nf.ID || !got.ExpiresAt.Equal(nf.ExpiresAt) || !slices.Equal(got.PendingTypes, []string{"email", "phone"}) {
		t.Errorf("started = %+v; want the flow's id, expiry and pending types", got)
	}
	if len(got.Handle) != 43 || !bytes.Equal(nf.HandleHash, sha(got.Handle)) {
		t.Errorf("handle of %d characters; the flow must store its SHA-256", len(got.Handle))
	}
	// One challenge per identifier, by the type's method, each sent once.
	var methods []flow.Method
	for _, c := range e.flows.opened {
		methods = append(methods, c.Method)
		if c.FlowID != nf.ID || e.flows.sends[c.ID] != 1 {
			t.Errorf("challenge %v: flow %v, %d sends; want the flow and one send", c.ID, c.FlowID, e.flows.sends[c.ID])
		}
	}
	if !slices.Equal(methods, []flow.Method{flow.MethodEmailLink, flow.MethodSMSOTP}) {
		t.Errorf("methods = %v; want [email_link sms_otp]", methods)
	}
	if len(e.outbox.requests) != 2 {
		t.Errorf("wrote %d delivery requests; want 2", len(e.outbox.requests))
	}
	if n := e.limiter.Hits(app.RuleRegistrationIP, "192.0.2.10"); n != 1 {
		t.Errorf("L-4 hits = %d; want 1", n)
	}
	if n := e.limiter.Hits(app.RuleSendIP, "192.0.2.10"); n != 2 {
		t.Errorf("L-8 hits = %d; want one per identifier", n)
	}
	if len(e.audit.entries) != 1 || e.audit.entries[0].Outcome != app.OutcomeSuccess || e.audit.entries[0].AccountID != na.ID {
		t.Errorf("audit = %+v; want one success about the account", e.audit.entries)
	}
}

func TestStartRegistrationSkipsRefusedSend(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	e.flows.counts = app.SendCounts{Short: 1, Long: 1} // someone else sent to these values a moment ago
	got, err := e.reg.Start(context.Background(), startCmd())
	if err != nil {
		t.Fatalf("Start = %v; want the registration created, its sends skipped (TDD-02 §3)", err)
	}
	if len(e.flows.opened) != 2 || len(e.flows.sends) != 0 || len(e.outbox.requests) != 0 {
		t.Errorf("opened %d, sent %v, wrote %d; want two open, unsent challenges", len(e.flows.opened), e.flows.sends, len(e.outbox.requests))
	}
	if len(got.PendingTypes) != 2 {
		t.Errorf("pending = %v", got.PendingTypes)
	}
}

func TestStartRegistrationErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		edit   func(*app.StartRegistration, *regEnv)
		code   domain.Code
		fields []domain.FieldError
		hashed bool
	}{
		{"unknown client", func(c *app.StartRegistration, _ *regEnv) { c.ClientID = "nope" }, domain.CodeValidationFailed,
			[]domain.FieldError{{Field: "client_id", Code: domain.FieldUnknown}}, false},
		{"client without self-registration", func(c *app.StartRegistration, _ *regEnv) { c.ClientID = "console" },
			domain.CodeValidationFailed, []domain.FieldError{{Field: "client_id", Code: domain.FieldUnknown}}, false},
		{"registration window full", func(_ *app.StartRegistration, e *regEnv) {
			for range 5 {
				_, _ = e.limiter.Hit(context.Background(), app.RuleRegistrationIP, "192.0.2.10", app.RateLimit{Limit: 5, Window: time.Hour})
			}
		}, domain.CodeRateLimited, nil, false},
		{"locale not allowed", func(c *app.StartRegistration, _ *regEnv) { c.Locale = "fr" }, domain.CodeValidationFailed,
			[]domain.FieldError{{Field: "locale", Code: domain.FieldUnknown}}, false},
		{"required type missing", func(c *app.StartRegistration, _ *regEnv) { delete(c.Identifiers, "email") },
			domain.CodeValidationFailed, []domain.FieldError{{Field: "identifiers.email", Code: domain.FieldRequired}}, false},
		{"unknown type", func(c *app.StartRegistration, _ *regEnv) { c.Identifiers["username"] = "someone" },
			domain.CodeIdentifierNotAllowed, nil, false},
		{"value not allowed", func(c *app.StartRegistration, _ *regEnv) { c.Identifiers["phone"] = "+1 202 555 0100" },
			domain.CodeIdentifierNotAllowed, nil, false},
		{"value taken", func(_ *app.StartRegistration, e *regEnv) { e.accounts.verified["phone:+447400123456"] = true },
			domain.CodeIdentifierTaken, nil, false},
		{"password holds the email", func(c *app.StartRegistration, _ *regEnv) { c.Password = flow.Secret("someone@example.com!") },
			domain.CodePasswordRejected, nil, false},
		{"common password", func(c *app.StartRegistration, _ *regEnv) { c.Password = flow.Secret("password1234") },
			domain.CodePasswordRejected, nil, false},
		{"send window full", func(_ *app.StartRegistration, e *regEnv) {
			for range 20 {
				_, _ = e.limiter.Hit(context.Background(), app.RuleSendIP, "192.0.2.10", app.RateLimit{Limit: 20, Window: time.Hour})
			}
		}, domain.CodeRateLimited, nil, false},
		{"hasher overloaded", func(_ *app.StartRegistration, e *regEnv) { e.hasher.err = app.ErrOverloaded },
			domain.CodeUnavailable, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newRegEnv(t)
			cmd := startCmd()
			tt.edit(&cmd, e)
			_, err := e.reg.Start(context.Background(), cmd)
			var de *domain.Error
			if !errors.As(err, &de) || de.Code != tt.code {
				t.Fatalf("Start = %v; want %s", err, tt.code)
			}
			if diff := cmp.Diff(tt.fields, de.Fields); diff != "" {
				t.Errorf("fields (-want +got):\n%s", diff)
			}
			if got := e.hasher.hashes > 0; got != tt.hashed {
				t.Errorf("hashed = %v; want %v (checks before hashing, TDD-07 §2)", got, tt.hashed)
			}
			if len(e.accounts.created) != 0 {
				t.Error("an account was created")
			}
			for _, v := range []string{regEmail, "someone@example.com", "+447400123456", string(cmd.Password)} {
				if strings.Contains(err.Error(), v) {
					t.Errorf("error %q holds a value", err)
				}
			}
		})
	}
}

func sha(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// started starts the default registration and returns it.
func (e *regEnv) started(t *testing.T) app.RegistrationStarted {
	t.Helper()
	s, err := e.reg.Start(context.Background(), startCmd())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// opened returns the newest challenge opened on the identifier of type typ.
func (e *regEnv) opened(t *testing.T, typ string) flow.NewChallengeRecord {
	t.Helper()
	for i := len(e.flows.opened) - 1; i >= 0; i-- {
		if e.flows.opened[i].TargetType == typ {
			return e.flows.opened[i]
		}
	}
	t.Fatalf("no challenge on %s", typ)
	return flow.NewChallengeRecord{}
}

func (e *regEnv) verify(s app.RegistrationStarted, code string) (app.RegistrationProgress, error) {
	return e.reg.VerifyCode(context.Background(), app.VerifyRegistrationCode{
		FlowID: s.FlowID, Handle: s.Handle, IdentifierType: "phone", Code: flow.Secret(code), IP: regIP,
	})
}

func (e *regEnv) resend(s app.RegistrationStarted, typ string) error {
	return e.reg.Resend(context.Background(), app.ResendRegistration{
		FlowID: s.FlowID, Handle: s.Handle, IdentifierType: typ, IP: regIP,
	})
}

const rightCode, wrongCode = "777777", "000000" // every random byte the tests draw is 7

func wantCode(t *testing.T, err error, code domain.Code) {
	t.Helper()
	_ = asCode(t, err, code)
}

// asCode fails the test unless err is a *domain.Error with code, and returns it.
func asCode(t *testing.T, err error, code domain.Code) *domain.Error {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != code {
		t.Fatalf("got %v; want %s", err, code)
	}
	return de
}

func TestVerifyCode(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	got, err := e.verify(s, rightCode)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.PendingTypes, []string{"email"}) {
		t.Errorf("pending = %v; want [email]", got.PendingTypes)
	}
	ch := e.flows.challenge(e.opened(t, "phone").ID)
	if ch.ConsumedAt == nil || ch.Attempts != 1 {
		t.Errorf("challenge = %+v; want consumed after one attempt", ch.Challenge)
	}
	phone := e.accounts.ids[1]
	if phone.Type != "phone" || phone.VerifiedAt == nil {
		t.Errorf("phone identifier = %+v; want verified", phone)
	}
	if st := e.flows.byID[s.FlowID].State.(flow.RegistrationState); !slices.Equal(st.PendingTypes, []string{"email"}) {
		t.Errorf("stored pending = %v; want [email]", st.PendingTypes)
	}
	want := []recordedEvent{{app.EventIdentifierVerified, phone.AccountID, app.IdentifierVerified{
		AccountID: phone.AccountID, IdentifierID: phone.ID, IdentifierType: "phone",
		Actor: app.EventActor{Kind: app.ActorAccount, ID: phone.AccountID.String()},
	}}}
	if diff := cmp.Diff(want, e.outbox.events); diff != "" {
		t.Errorf("events (-want +got):\n%s", diff)
	}
	// I-4: consumed at most once.
	_, err = e.verify(s, rightCode)
	wantCode(t, err, domain.CodeChallengeClosed)
	if len(e.outbox.events) != 1 {
		t.Errorf("%d events; want 1", len(e.outbox.events))
	}
}

func TestVerifyCodeAttempts(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	for _, left := range []int{2, 1} {
		_, err := e.verify(s, wrongCode)
		if de := asCode(t, err, domain.CodeCodeInvalid); de.AttemptsLeft == nil || *de.AttemptsLeft != left {
			t.Fatalf("attempts_left = %v; want %d", de.AttemptsLeft, left)
		}
	}
	_, err := e.verify(s, wrongCode)
	wantCode(t, err, domain.CodeChallengeClosed)
	if ch := e.flows.challenge(e.opened(t, "phone").ID); ch.ClosedAt == nil || ch.ConsumedAt != nil || ch.Attempts != 3 {
		t.Errorf("challenge = %+v; want closed unconsumed after 3 attempts", ch.Challenge)
	}
	// I-4: no fourth try, even with the right code.
	_, err = e.verify(s, rightCode)
	wantCode(t, err, domain.CodeChallengeClosed)
	if e.accounts.ids[1].VerifiedAt != nil {
		t.Error("the phone was verified after the attempts ran out")
	}
}

func TestVerifyCodeTakenConsumes(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	e.accounts.verified["phone:+447400123456"] = true // another account verified it first (T-1)
	_, err := e.verify(s, rightCode)
	wantCode(t, err, domain.CodeIdentifierTaken)
	if ch := e.flows.challenge(e.opened(t, "phone").ID); ch.ConsumedAt == nil {
		t.Error("the challenge was not consumed (TDD-02 §3)")
	}
	if len(e.outbox.events) != 0 {
		t.Errorf("events = %v; want none", e.outbox.events)
	}
	_, err = e.verify(s, rightCode)
	wantCode(t, err, domain.CodeChallengeClosed)
}

func TestVerifyCodeSameMiss(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(*app.VerifyRegistrationCode, *regEnv)
	}{
		{"wrong handle", func(c *app.VerifyRegistrationCode, _ *regEnv) { c.Handle = bytes.Repeat([]byte("A"), 43) }},
		{"unknown flow", func(c *app.VerifyRegistrationCode, _ *regEnv) { c.FlowID = fakes.ID(999) }},
		{"expired flow", func(_ *app.VerifyRegistrationCode, e *regEnv) { e.clock.Advance(25 * time.Hour) }},
		{"type not pending", func(c *app.VerifyRegistrationCode, _ *regEnv) { c.IdentifierType = "username" }},
		{"link-verified type", func(c *app.VerifyRegistrationCode, _ *regEnv) { c.IdentifierType = "email" }},
		{"flow of another kind", func(c *app.VerifyRegistrationCode, e *regEnv) {
			e.flows.byID[c.FlowID].Kind = flow.KindSignIn // its own handle opens it, but not here
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newRegEnv(t)
			s := e.started(t)
			cmd := app.VerifyRegistrationCode{FlowID: s.FlowID, Handle: s.Handle, IdentifierType: "phone",
				Code: flow.Secret(rightCode), IP: regIP}
			tt.edit(&cmd, e)
			_, err := e.reg.VerifyCode(context.Background(), cmd)
			if de := asCode(t, err, domain.CodeChallengeClosed); de.Detail != "the challenge is closed" {
				t.Errorf("detail %q; want the one every miss gives (I-20)", de.Detail)
			}
		})
	}
}

func TestVerifyCodeRateLimited(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	for range 30 {
		_, _ = e.limiter.Hit(context.Background(), app.RuleVerifyIP, "192.0.2.10", app.RateLimit{Limit: 30, Window: time.Hour})
	}
	_, err := e.verify(s, rightCode)
	wantCode(t, err, domain.CodeRateLimited)
	if e.flows.challenge(e.opened(t, "phone").ID).Attempts != 0 {
		t.Error("a refused attempt counted on the challenge")
	}
}

func TestResend(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	first := e.opened(t, "phone").ID

	err := e.resend(s, "phone")
	if de := asCode(t, err, domain.CodeResendTooSoon); de.RetryAfter != time.Minute {
		t.Errorf("retry_after = %v; want 60s", de.RetryAfter)
	}

	e.clock.Advance(61 * time.Second)
	if err := e.resend(s, "phone"); err != nil {
		t.Fatalf("resend after 61s: %v", err)
	}
	if c := e.flows.challenge(first); c.Sends != 2 || len(e.flows.opened) != 2 {
		t.Errorf("sends = %d, %d challenges; want the open one reused", c.Sends, len(e.flows.opened))
	}

	e.clock.Advance(5 * time.Minute) // the code expired
	if err := e.resend(s, "phone"); err != nil {
		t.Fatalf("resend after expiry: %v", err)
	}
	if c := e.flows.challenge(first); c.ClosedAt == nil {
		t.Error("the expired challenge stays open")
	}
	second := e.opened(t, "phone").ID
	if second == first || e.flows.challenge(second).Sends != 1 {
		t.Errorf("want a new challenge, sent once")
	}
	if n := e.limiter.Hits(app.RuleSendIP, "192.0.2.10"); n != 5 {
		t.Errorf("L-8 hits = %d; want 2 at start and one per resend", n)
	}

	// Exhaust it: resends wait for the cooldown.
	for range 3 {
		_, _ = e.verify(s, wrongCode)
	}
	err = e.resend(s, "phone")
	if de := asCode(t, err, domain.CodeResendTooSoon); de.RetryAfter != 15*time.Minute {
		t.Errorf("retry_after = %v; want the 15 min cooldown", de.RetryAfter)
	}
	e.clock.Advance(15 * time.Minute)
	if err := e.resend(s, "phone"); err != nil {
		t.Fatalf("resend after the cooldown: %v", err)
	}

	// A verified type has nothing to resend.
	if _, err := e.verify(s, rightCode); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.resend(s, "phone"), domain.CodeChallengeClosed)
}

// TestResendLimited: a resend refused by the address's hour budget answers RATE_LIMITED and counts
// no send. The rollback of a replaced challenge is TestResendRefusedRollsBack, on PostgreSQL.
func TestResendLimited(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	e.clock.Advance(time.Minute)
	e.flows.counts = app.SendCounts{Short: 0, Long: 5} // other accounts used the value's hour budget (I-21)
	wantCode(t, e.resend(s, "phone"), domain.CodeRateLimited)
	if c := e.flows.challenge(e.opened(t, "phone").ID); c.Sends != 1 {
		t.Errorf("sends = %d; a refused resend counted", c.Sends)
	}
}

func TestConfirmLink(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	token := e.opened(t, "email").Secret
	confirm := func() (app.LinkConfirmed, error) {
		return e.reg.ConfirmLink(context.Background(), app.ConfirmLink{Token: token, IP: regIP})
	}
	got, err := confirm()
	if err != nil {
		t.Fatal(err)
	}
	want := app.LinkConfirmed{Purpose: flow.PurposeVerifyIdentifier, FlowID: s.FlowID, PendingTypes: []string{"phone"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("confirmed (-want +got):\n%s", diff)
	}
	if e.accounts.ids[0].Type != "email" || e.accounts.ids[0].VerifiedAt == nil || len(e.outbox.events) != 1 {
		t.Error("the email was not verified with its event")
	}
	_, err = confirm()
	wantCode(t, err, domain.CodeChallengeClosed)

	if _, err := e.verify(s, rightCode); err != nil {
		t.Fatal(err)
	}
	if st := e.flows.byID[s.FlowID].State.(flow.RegistrationState); len(st.PendingTypes) != 0 {
		t.Errorf("pending = %v; want none", st.PendingTypes)
	}
}

func TestConfirmLinkUnknownToken(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	e.started(t)
	_, err := e.reg.ConfirmLink(context.Background(), app.ConfirmLink{Token: bytes.Repeat([]byte("B"), 43), IP: regIP})
	wantCode(t, err, domain.CodeChallengeClosed)
}

// TestVerifyCodeExpired: a code past its expiry is CHALLENGE_CLOSED, without a try counted; the
// repository's Attempt does not look at expires_at, so the decision is the only guard.
func TestVerifyCodeExpired(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	e.clock.Advance(challengeRules.OTPTTL + time.Second)
	_, err := e.verify(s, rightCode)
	wantCode(t, err, domain.CodeChallengeClosed)
	if ch := e.flows.challenge(e.opened(t, "phone").ID); ch.Attempts != 0 || ch.ConsumedAt != nil {
		t.Errorf("challenge = %+v; want untouched", ch.Challenge)
	}
	if e.accounts.ids[1].VerifiedAt != nil {
		t.Error("an expired code verified the phone")
	}
}

// TestFailureAuditLostIsLogged: a refusal whose audit write fails still answers its domain error,
// alone, and the lost entry is logged.
func TestFailureAuditLostIsLogged(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	e.audit.err = errors.New("audit table gone")
	cmd := startCmd()
	cmd.ClientID = "nope"
	_, err := e.reg.Start(context.Background(), cmd)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeValidationFailed || err.Error() != de.Error() {
		t.Fatalf("Start = %v; want the VALIDATION_FAILED answer alone", err)
	}
	if logs := e.logs.String(); !strings.Contains(logs, "audit write failed") || !strings.Contains(logs, "audit table gone") {
		t.Errorf("logs %q; want the lost audit entry logged", logs)
	}
}

// TestInfrastructureErrorNotAudited: a store failure before the transaction is not a refusal: it
// is returned wrapped, with no audit entry.
func TestInfrastructureErrorNotAudited(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	before := len(e.audit.entries)
	e.flows.findErr = errors.New("connection reset")
	_, err := e.verify(s, rightCode)
	var de *domain.Error
	if err == nil || errors.As(err, &de) || !strings.Contains(err.Error(), "connection reset") ||
		!strings.Contains(err.Error(), "verify registration code") {
		t.Fatalf("VerifyCode = %v; want the store error, wrapped", err)
	}
	if len(e.audit.entries) != before {
		t.Errorf("audited %d entries for an outage", len(e.audit.entries)-before)
	}
}

// TestResendRollbackFailureSurfaces: when rolling back a refused resend fails, that failure is the
// answer, not the refusal.
func TestResendRollbackFailureSurfaces(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	e.clock.Advance(time.Minute)
	e.flows.counts = app.SendCounts{Long: 5}
	e.uow.rollbackErr = errors.New("roll back: connection lost")
	err := e.resend(s, "phone")
	if err == nil || hasDomainCode(err, domain.CodeRateLimited) || !strings.Contains(err.Error(), "connection lost") {
		t.Fatalf("Resend = %v; want the rollback failure", err)
	}
}

// TestResendTypeNoLongerConfigured: a pending identifier whose type the policy dropped since is
// the same miss, not a panic.
func TestResendTypeNoLongerConfigured(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	e.accounts.ids[1].Type = "fax"
	st := e.flows.byID[s.FlowID].State.(flow.RegistrationState)
	e.flows.byID[s.FlowID].State = flow.RegistrationState{PendingTypes: append(st.PendingTypes, "fax")}
	wantCode(t, e.resend(s, "fax"), domain.CodeChallengeClosed)
}

// TestVerifyAccountGone: an account that disappears between the find and the lock is the same
// miss (I-20), not NOT_FOUND.
func TestVerifyAccountGone(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	delete(e.accounts.accounts, e.accounts.created[0].ID)
	_, err := e.verify(s, rightCode)
	wantCode(t, err, domain.CodeChallengeClosed)
}

// TestNewRegistrationRefusesMissingDeps: every port is required, and a missing one is named at
// start-up rather than found by the first request.
func TestNewRegistrationRefusesMissingDeps(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	d := e.deps
	d.Limits, d.Logger = nil, nil
	_, err := app.NewRegistration(d, e.opts)
	if err == nil || !strings.Contains(err.Error(), "Limits") || !strings.Contains(err.Error(), "Logger") {
		t.Errorf("NewRegistration = %v; want an error naming Limits and Logger", err)
	}
	o := e.opts
	o.FlowTTL = 0
	if _, err := app.NewRegistration(e.deps, o); err == nil {
		t.Error("NewRegistration accepted a zero flow lifetime")
	}
	for _, l := range []account.FactorLimit{{Window: time.Hour}, {Limit: 10}} {
		o := e.opts
		o.FactorLimit = l
		if _, err := app.NewRegistration(e.deps, o); err == nil {
			t.Errorf("NewRegistration accepted the factor limit %+v", l)
		}
	}
}

// TestNewRegistrationCopiesOptions: the options' map and slice are the caller's no more.
func TestNewRegistrationCopiesOptions(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	o := e.opts
	o.Clients = map[string]app.RegistrationClient{"web": {ID: "web", SelfRegistration: true}}
	o.Locales = []string{"en-GB"}
	reg, err := app.NewRegistration(e.deps, o)
	if err != nil {
		t.Fatal(err)
	}
	o.Clients["web"] = app.RegistrationClient{ID: "web"}
	o.Locales[0] = "fr"
	if _, err := reg.Start(context.Background(), startCmd()); err != nil {
		t.Errorf("Start after the caller changed its options: %v", err)
	}
}

func hasDomainCode(err error, code domain.Code) bool {
	var de *domain.Error
	return errors.As(err, &de) && de.Code == code
}

// TestRegistrationAuditsRefusals: a refusal is audited with its code, and with the flow's id and
// kind once the flow was found; a refusal by a per-IP limit is not audited.
func TestRegistrationAuditsRefusals(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	audited := func() []app.AuditEntry { return e.audit.entries[1:] } // after Start's success

	_, _ = e.verify(s, wrongCode)
	_, _ = e.reg.VerifyCode(context.Background(), app.VerifyRegistrationCode{FlowID: fakes.ID(999), Handle: s.Handle,
		IdentifierType: "phone", Code: flow.Secret(rightCode), IP: regIP})
	for range 30 {
		_, _ = e.limiter.Hit(context.Background(), app.RuleVerifyIP, "192.0.2.10", app.RateLimit{Limit: 30, Window: time.Hour})
	}
	_, _ = e.verify(s, rightCode) // L-12 refuses: not audited

	got := audited()
	if len(got) != 2 {
		t.Fatalf("%d entries after the start; want 2: %+v", len(got), got)
	}
	want := []app.AuditEntry{
		{ActorKind: app.ActorAnonymous, Action: "registration.verify", Outcome: app.OutcomeFailure, ClientID: "web", IP: regIP,
			Details: map[string]any{"identifier_type": "phone", "flow_id": s.FlowID.String(), "kind": "registration", "code": "CODE_INVALID"}},
		{ActorKind: app.ActorAnonymous, Action: "registration.verify", Outcome: app.OutcomeFailure, IP: regIP,
			Details: map[string]any{"identifier_type": "phone", "code": "CHALLENGE_CLOSED"}},
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
		t.Errorf("audit (-want +got):\n%s", diff)
	}
}

func TestConfirmLinkRateLimited(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	e.started(t)
	for range 30 {
		_, _ = e.limiter.Hit(context.Background(), app.RuleVerifyIP, "192.0.2.10", app.RateLimit{Limit: 30, Window: time.Hour})
	}
	_, err := e.reg.ConfirmLink(context.Background(), app.ConfirmLink{Token: e.opened(t, "email").Secret, IP: regIP})
	wantCode(t, err, domain.CodeRateLimited)
	if e.accounts.ids[0].VerifiedAt != nil {
		t.Error("a refused confirmation verified the email")
	}
}

// TestConfirmLinkSameMiss (I-20): a link of another purpose, a link into a flow of another kind,
// and a link that closed between the find and the lock all answer the same CHALLENGE_CLOSED.
func TestConfirmLinkSameMiss(t *testing.T) {
	t.Parallel()
	for name, edit := range map[string]func(*regEnv, app.RegistrationStarted){
		"other purpose": func(e *regEnv, _ app.RegistrationStarted) {
			e.flows.challenge(e.opened(t, "email").ID).Purpose = flow.PurposeEmailChangeNew
		},
		"other flow kind": func(e *regEnv, s app.RegistrationStarted) { e.flows.byID[s.FlowID].Kind = flow.KindEmailChange },
		"closed before the lock": func(e *regEnv, _ app.RegistrationStarted) {
			e.flows.afterFindLink = func(c *flow.ChallengeRecord) {
				closed := e.clock.Now()
				c.ClosedAt = &closed
			}
		},
		"expired before the lock": func(e *regEnv, _ app.RegistrationStarted) {
			e.flows.afterFindLink = func(*flow.ChallengeRecord) { e.clock.Advance(challengeRules.LinkTTL) }
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newRegEnvLongFlow(t)
			s := e.started(t)
			edit(e, s)
			_, err := e.reg.ConfirmLink(context.Background(), app.ConfirmLink{Token: e.opened(t, "email").Secret, IP: regIP})
			if de := asCode(t, err, domain.CodeChallengeClosed); de.Detail != "the challenge is closed" {
				t.Errorf("detail %q", de.Detail)
			}
			if e.accounts.ids[0].VerifiedAt != nil {
				t.Error("the email was verified")
			}
		})
	}
}

// newRegEnvLongFlow is newRegEnv with flows that outlive their links, so that a link can expire
// in an open flow.
func newRegEnvLongFlow(t *testing.T) *regEnv {
	t.Helper()
	e := newRegEnv(t)
	o := e.opts
	o.FlowTTL = 48 * time.Hour
	reg, err := app.NewRegistration(e.deps, o)
	if err != nil {
		t.Fatal(err)
	}
	e.reg = reg
	return e
}

func TestConfirmLinkComplete(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	if _, err := e.verify(s, rightCode); err != nil {
		t.Fatal(err)
	}
	got, err := e.reg.ConfirmLink(context.Background(), app.ConfirmLink{Token: e.opened(t, "email").Secret, IP: regIP})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete || len(got.PendingTypes) != 0 || got.PendingTypes == nil {
		t.Errorf("confirmed = %+v; want complete with an empty, non-nil list", got)
	}
}

// TestVerifyInvitationFlow: the registration steps serve invitation flows too (TDD-02 §8), keeping
// the invitation's own state.
func TestVerifyInvitationFlow(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	s := e.started(t)
	f := e.flows.byID[s.FlowID]
	f.Kind = flow.KindInvitation
	f.State = flow.InvitationState{Roles: []string{"user"}, Accepted: true, PendingTypes: []string{"email", "phone"}}
	got, err := e.verify(s, rightCode)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.PendingTypes, []string{"email"}) {
		t.Errorf("pending = %v", got.PendingTypes)
	}
	want := flow.InvitationState{Roles: []string{"user"}, Accepted: true, PendingTypes: []string{"email"}}
	if diff := cmp.Diff(flow.State(want), f.State); diff != "" {
		t.Errorf("state (-want +got):\n%s", diff)
	}
}

// TestVerifyEmailCode: an email verified by code goes through VerifyCode like a phone.
func TestVerifyEmailCode(t *testing.T) {
	t.Parallel()
	e := newRegEnvEmail(t, identifier.Policy{Required: true, Verify: flow.MethodEmailCode, SignIn: true})
	s := e.started(t)
	if m := e.opened(t, "email").Method; m != flow.MethodEmailCode {
		t.Fatalf("email challenge by %s; want email_code", m)
	}
	if typ := e.outbox.requests[0].Type; typ != "auth.email_verification_code" {
		t.Errorf("message type %q", typ)
	}
	got, err := e.reg.VerifyCode(context.Background(), app.VerifyRegistrationCode{FlowID: s.FlowID, Handle: s.Handle,
		IdentifierType: "email", Code: flow.Secret(rightCode), IP: regIP})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.PendingTypes, []string{"phone"}) || e.accounts.ids[0].VerifiedAt == nil {
		t.Errorf("pending = %v; want the email verified", got.PendingTypes)
	}
}

// TestStartRegistrationSkipsHourBudget: a send refused by the address's hour budget is skipped
// like one refused by the short window.
func TestStartRegistrationSkipsHourBudget(t *testing.T) {
	t.Parallel()
	e := newRegEnv(t)
	e.flows.counts = app.SendCounts{Long: 5}
	e.started(t)
	if len(e.flows.opened) != 2 || len(e.outbox.requests) != 0 {
		t.Errorf("opened %d, wrote %d; want two open, unsent challenges", len(e.flows.opened), len(e.outbox.requests))
	}
	if got := e.audit.entries[0].Details["unsent_types"]; !cmp.Equal(got, []string{"email", "phone"}) {
		t.Errorf("unsent_types = %v", got)
	}
}

// TestResendEmailLinkAfterExpiry: an expired link is replaced by a new link challenge, with the
// link lifetime.
func TestResendEmailLinkAfterExpiry(t *testing.T) {
	t.Parallel()
	e := newRegEnvLongFlow(t)
	s := e.started(t)
	first := e.opened(t, "email")
	e.clock.Advance(challengeRules.LinkTTL + time.Second)
	if err := e.resend(s, "email"); err != nil {
		t.Fatal(err)
	}
	second := e.opened(t, "email")
	if second.ID == first.ID || second.Method != flow.MethodEmailLink || !second.ExpiresAt.Equal(e.clock.Now().Add(challengeRules.LinkTTL)) {
		t.Errorf("new challenge = %+v; want a new link, living the link lifetime", second)
	}
	if e.flows.challenge(first.ID).ClosedAt == nil {
		t.Error("the expired link stays open")
	}
}
