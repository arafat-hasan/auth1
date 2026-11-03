package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
type fakeUoW struct{ inTx bool }

func (u *fakeUoW) Do(ctx context.Context, fn func(context.Context) error) error {
	if u.inTx {
		return fn(ctx)
	}
	u.inTx = true
	defer func() { u.inTx = false }()
	return fn(ctx)
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

// regAccounts is the accounts repository of the registration tests: verified values, the accounts
// created and their identifiers.
type regAccounts struct {
	app.Accounts
	verified map[string]bool // type:value held verified by another account
	created  []account.NewAccount
	accounts map[uuid.UUID]account.Account
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
	return nil
}

func (a *regAccounts) GetForUpdate(_ context.Context, id uuid.UUID) (account.Account, error) {
	acc, ok := a.accounts[id]
	if !ok {
		return account.Account{}, &domain.Error{Code: domain.CodeNotFound}
	}
	return acc, nil
}

// regFlows records the flows opened, on top of sendFlows.
type regFlows struct {
	*sendFlows
	flows []flow.NewFlow
}

func (f *regFlows) Open(_ context.Context, nf flow.NewFlow) error {
	f.flows = append(f.flows, nf)
	return nil
}

// recordingAudit keeps the entries written.
type recordingAudit struct{ entries []app.AuditEntry }

func (a *recordingAudit) Write(_ context.Context, e app.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type regEnv struct {
	reg      *app.Registration
	uow      *fakeUoW
	accounts *regAccounts
	flows    *regFlows
	outbox   *recordingOutbox
	audit    *recordingAudit
	hasher   *fakeHasher
	limiter  *fakes.RateLimiter
	clock    *fakes.Clock
}

const (
	regEmail    = "Someone@Example.com"
	regPhone    = "+44 7400 123456"
	regPassword = "correct horse battery staple"
)

func newRegEnv(t *testing.T) *regEnv {
	t.Helper()
	types, errs := message.NewTypes(nil)
	if errs != nil {
		t.Fatal(errs)
	}
	registry, err := identifier.NewRegistry(identifier.Builtin(), map[string]identifier.Policy{
		"email": emailPol, "phone": phonePol,
	})
	if err != nil {
		t.Fatal(err)
	}
	deny, err := password.ParseDenyList(strings.NewReader("password1234\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := &regEnv{
		uow: &fakeUoW{}, accounts: &regAccounts{verified: map[string]bool{}},
		flows: &regFlows{sendFlows: &sendFlows{}}, outbox: &recordingOutbox{}, audit: &recordingAudit{},
		limiter: fakes.NewRateLimiter(), clock: fakes.NewClock(now),
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
	ch := app.NewChallenges(e.flows, e.outbox, app.NewMessages(types), testMAC{}, ids, e.clock, rnd, challengeRules)
	e.reg = app.NewRegistration(app.RegistrationDeps{
		UnitOfWork: e.uow, Accounts: e.accounts, Flows: e.flows, Challenges: ch, Outbox: e.outbox,
		Audit: e.audit, Hasher: e.hasher, Registry: registry, Limits: limits, IDs: ids, Clock: e.clock,
		Rand: rnd, MAC: testMAC{},
	}, app.RegistrationOptions{
		Clients: map[string]app.RegistrationClient{
			"web": {ID: "web", SelfRegistration: true}, "console": {ID: "console"},
		},
		Locales:  []string{"en", "en-GB"},
		FlowTTL:  24 * time.Hour,
		Password: password.Policy{MinLength: 12, MaxLength: 128, DenyList: deny},
		Resend:   flow.ResendRules{ResendAfter: time.Minute, Cooldown: 15 * time.Minute},
	})
	return e
}

var regIP = netip.MustParseAddr("192.0.2.10")

func startCmd() app.StartRegistration {
	return app.StartRegistration{
		ClientID: "web", DisplayName: "Someone", Locale: "en-GB",
		Identifiers: map[string]string{"email": regEmail, "phone": regPhone},
		Password:    []byte(regPassword), IP: regIP, UserAgent: "test",
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
		{"password holds the email", func(c *app.StartRegistration, _ *regEnv) { c.Password = []byte("someone@example.com!") },
			domain.CodePasswordRejected, nil, false},
		{"common password", func(c *app.StartRegistration, _ *regEnv) { c.Password = []byte("password1234") },
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
