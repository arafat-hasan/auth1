package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/identifier"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/domain/session"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// The sign-in tests run app.SignIn on in-memory stores. The account is active, holds the
// verified email signInEmail and the password signInPassword (stored as "phc:<password>" under
// pepper key "1"), and the role member.

const (
	signInEmail    = "ada@example.org"
	signInPassword = "correct horse battery staple"
)

var signInIP = netip.MustParseAddr("192.0.2.20")

// signAccounts is the accounts repository of the sign-in tests. beforeLock runs at the start of
// GetForUpdate, to change the account between the unlocked reads and the lock.
type signAccounts struct {
	app.Accounts
	uow        *fakeUoW
	verified   map[string]account.Identifier // "type:value"
	accounts   map[uuid.UUID]account.Account
	creds      map[uuid.UUID]account.PasswordCredential
	roles      map[uuid.UUID][]string
	totp       map[uuid.UUID]account.TOTPFactor
	locked     []uuid.UUID
	rehashed   []string
	beforeLock func()
}

func notFound() error { return &domain.Error{Code: domain.CodeNotFound} }

func (a *signAccounts) FindVerified(_ context.Context, idType, value string) (account.Identifier, error) {
	if id, ok := a.verified[idType+":"+value]; ok {
		return id, nil
	}
	return account.Identifier{}, notFound()
}

func (a *signAccounts) Get(_ context.Context, id uuid.UUID) (account.Account, error) {
	if acc, ok := a.accounts[id]; ok {
		return acc, nil
	}
	return account.Account{}, notFound()
}

func (a *signAccounts) GetForUpdate(ctx context.Context, id uuid.UUID) (account.Account, error) {
	if !a.uow.inTx {
		return account.Account{}, errors.New("GetForUpdate outside the transaction")
	}
	if a.beforeLock != nil {
		a.beforeLock()
	}
	a.locked = append(a.locked, id)
	return a.Get(ctx, id)
}

func (a *signAccounts) PasswordCredential(_ context.Context, id uuid.UUID) (account.PasswordCredential, error) {
	if c, ok := a.creds[id]; ok {
		return c, nil
	}
	return account.PasswordCredential{}, notFound()
}

func (a *signAccounts) Roles(_ context.Context, id uuid.UUID) ([]account.Role, error) {
	var out []account.Role
	for _, r := range a.roles[id] {
		out = append(out, account.Role{Name: r})
	}
	return out, nil
}

func (a *signAccounts) TOTPFactor(_ context.Context, id uuid.UUID) (account.TOTPFactor, error) {
	if f, ok := a.totp[id]; ok {
		return f, nil
	}
	return account.TOTPFactor{}, notFound()
}

func (a *signAccounts) RehashPassword(_ context.Context, id uuid.UUID, oldHash, hash, kid string) (bool, error) {
	if !slices.Contains(a.locked, id) {
		return false, errors.New("RehashPassword without the account lock")
	}
	c := a.creds[id]
	if c.Hash != oldHash {
		return false, nil
	}
	a.rehashed = append(a.rehashed, hash)
	a.creds[id] = account.PasswordCredential{Hash: hash, PepperKID: kid}
	return true, nil
}

// Identifiers gives the notices their recipient: the verified email.
func (a *signAccounts) Identifiers(_ context.Context, id uuid.UUID) ([]account.Identifier, error) {
	var out []account.Identifier
	for _, i := range a.verified {
		if i.AccountID == id {
			out = append(out, i)
		}
	}
	return out, nil
}

// signFlows records the sign-in flows opened and completed.
type signFlows struct {
	app.Flows
	uow       *fakeUoW
	opened    []flow.NewFlow
	completed []uuid.UUID
}

func (f *signFlows) Open(_ context.Context, nf flow.NewFlow) error {
	if !f.uow.inTx {
		return errors.New("Open outside the transaction")
	}
	f.opened = append(f.opened, nf)
	return nil
}

func (f *signFlows) Complete(_ context.Context, id uuid.UUID) error {
	f.completed = append(f.completed, id)
	return nil
}

// signSessions records the sessions created.
type signSessions struct {
	app.Sessions
	uow     *fakeUoW
	created []session.NewSession
	hashes  [][]byte
}

func (s *signSessions) Create(_ context.Context, ns session.NewSession, tokenHash []byte) error {
	if !s.uow.inTx {
		return errors.New("Create outside the transaction")
	}
	s.created = append(s.created, ns)
	s.hashes = append(s.hashes, tokenHash)
	return nil
}

// fakeThrottles keeps buckets in memory, on the test clock.
type fakeThrottles struct {
	uow      *fakeUoW
	clock    *fakes.Clock
	failures map[string]int
	until    map[string]time.Time
	known    map[string]bool // "account:device"
	resets   []account.Bucket
}

func newFakeThrottles(uow *fakeUoW, clock *fakes.Clock) *fakeThrottles {
	return &fakeThrottles{uow: uow, clock: clock, failures: map[string]int{}, until: map[string]time.Time{},
		known: map[string]bool{}}
}

func bucketKey(id uuid.UUID, b account.Bucket) string { return id.String() + "|" + string(b) }

func (f *fakeThrottles) Delay(_ context.Context, id uuid.UUID, b account.Bucket) (time.Duration, error) {
	return max(f.until[bucketKey(id, b)].Sub(f.clock.Now()), 0), nil
}

func (f *fakeThrottles) Fail(_ context.Context, id uuid.UUID, b account.Bucket, p account.ThrottlePolicy) (int, error) {
	if !f.uow.inTx {
		return 0, errors.New("Fail outside the transaction")
	}
	k := bucketKey(id, b)
	f.failures[k]++
	if d := p.Delay(f.failures[k]); d > 0 {
		f.until[k] = f.clock.Now().Add(d)
	}
	return f.failures[k], nil
}

func (f *fakeThrottles) Reset(_ context.Context, id uuid.UUID, b account.Bucket) error {
	if !f.uow.inTx {
		return errors.New("Reset outside the transaction")
	}
	delete(f.failures, bucketKey(id, b))
	delete(f.until, bucketKey(id, b))
	f.resets = append(f.resets, b)
	return nil
}

func (f *fakeThrottles) ResetAll(context.Context, uuid.UUID) error { return errors.New("not used") }

func (f *fakeThrottles) KnownDevice(_ context.Context, id, device uuid.UUID, _ time.Duration) (bool, error) {
	return f.known[id.String()+":"+device.String()], nil
}

// signHasher verifies "phc:<password>"; a pepper key id other than "1" needs a rehash. It fails
// the test when called inside the transaction (G-4).
type signHasher struct {
	t        *testing.T
	uow      *fakeUoW
	verifies int
	dummies  int
	hashes   int
	err      error // returned by Verify and VerifyDummy when set
}

func (h *signHasher) inTx(op string) {
	if h.uow.inTx {
		h.t.Errorf("%s called inside the transaction (G-4)", op)
	}
}

func (h *signHasher) Hash(_ context.Context, pw []byte) (string, string, error) {
	h.inTx("Hash")
	h.hashes++
	return "phc:" + string(pw), "1", nil
}

func (h *signHasher) Verify(_ context.Context, phc, kid string, pw []byte) (bool, bool, error) {
	h.inTx("Verify")
	h.verifies++
	if h.err != nil {
		return false, false, h.err
	}
	ok := phc == "phc:"+string(pw)
	return ok, ok && kid != "1", nil
}

func (h *signHasher) VerifyDummy(_ context.Context, _ []byte) (bool, error) {
	h.inTx("VerifyDummy")
	h.dummies++
	return false, h.err
}

// fakeAccess issues "jwt:<session>" tokens, restricted for a restricted status.
type fakeAccess struct {
	grants []app.AccessGrant
}

func (f *fakeAccess) Issue(g app.AccessGrant) (app.AccessToken, error) {
	if g.Status != account.StatusActive && !account.Restricted(g.Status) {
		return app.AccessToken{}, fmt.Errorf("status %s", g.Status)
	}
	f.grants = append(f.grants, g)
	return app.AccessToken{Token: "jwt:" + g.SessionID.String(), ExpiresAt: now.Add(15 * time.Minute),
		Restricted: account.Restricted(g.Status)}, nil
}

type signEnv struct {
	signIn    *app.SignIn
	uow       *fakeUoW
	accounts  *signAccounts
	flows     *signFlows
	sessions  *signSessions
	throttles *fakeThrottles
	outbox    *recordingOutbox
	audit     *recordingAudit
	hasher    *signHasher
	access    *fakeAccess
	limiter   *fakes.RateLimiter
	devices   *app.DeviceCookies
	clock     *fakes.Clock
	deps      app.SignInDeps
	opts      app.SignInOptions
	accountID uuid.UUID
}

// signInClients are the clients of the sign-in tests: web (cookie transport, MFA optional),
// native (body transport), secure (MFA required) and otp (no password first factor).
var signInClients = map[string]app.SignInClient{
	"web":    {ID: "web", Audience: "https://web.example.com", AllowedRoles: []string{"member"}, Password: true},
	"native": {ID: "native", Audience: "https://app.example.com", AllowedRoles: []string{"member"}, Password: true, BodyTransport: true},
	"secure": {ID: "secure", Audience: "https://secure.example.com", AllowedRoles: []string{"member"}, Password: true, MFARequired: true},
	"otp":    {ID: "otp", Audience: "https://otp.example.com", AllowedRoles: []string{"member"}},
	"admin":  {ID: "admin", Audience: "https://admin.example.com", AllowedRoles: []string{"admin"}, Password: true},
}

func newSignInEnv(t *testing.T, newSignIn bool) *signEnv {
	t.Helper()
	registry, err := identifier.NewRegistry(identifier.Builtin(), map[string]identifier.Policy{
		"email": emailPol, "phone": phonePol,
	})
	if err != nil {
		t.Fatal(err)
	}
	types, errs := message.NewTypes(nil)
	if errs != nil {
		t.Fatal(errs)
	}
	clock := fakes.NewClock(now)
	uow := &fakeUoW{}
	ids := fakes.NewIDs()
	e := &signEnv{
		uow: uow, clock: clock, outbox: &recordingOutbox{}, audit: &recordingAudit{}, access: &fakeAccess{},
		accounts: &signAccounts{uow: uow, verified: map[string]account.Identifier{},
			accounts: map[uuid.UUID]account.Account{}, creds: map[uuid.UUID]account.PasswordCredential{},
			roles: map[uuid.UUID][]string{}, totp: map[uuid.UUID]account.TOTPFactor{}},
		flows: &signFlows{uow: uow}, sessions: &signSessions{uow: uow}, throttles: newFakeThrottles(uow, clock),
		limiter: fakes.NewRateLimiter(), accountID: ids.New(),
	}
	e.hasher = &signHasher{t: t, uow: uow}
	verified := now.Add(-time.Hour)
	e.accounts.verified["email:"+signInEmail] = account.Identifier{ID: ids.New(), AccountID: e.accountID,
		Type: "email", Value: signInEmail, VerifiedAt: &verified}
	e.accounts.accounts[e.accountID] = account.Account{ID: e.accountID, Status: account.StatusActive, Locale: "en", Version: 3}
	e.accounts.creds[e.accountID] = account.PasswordCredential{Hash: "phc:" + signInPassword, PepperKID: "1"}
	e.accounts.roles[e.accountID] = []string{"member"}
	if e.devices, err = app.NewDeviceCookies(hmacDevice("device key"), clock, ids); err != nil {
		t.Fatal(err)
	}
	notices := app.NewNotices(e.accounts, e.outbox, app.NewMessages(types), registry, clock,
		app.NoticeOptions{RetiredAddressWindow: window, NewSignIn: newSignIn})
	e.deps = app.SignInDeps{
		UnitOfWork: uow, Accounts: e.accounts, Flows: e.flows, Sessions: e.sessions, Throttles: e.throttles,
		Notices: notices, Audit: e.audit, Hasher: e.hasher, Registry: registry, Limits: newLimits(t, e.limiter, 30),
		Access: e.access, Devices: e.devices, IDs: ids, Clock: clock,
		Rand: bytes.NewReader(bytes.Repeat([]byte{9}, 1<<16)), Logger: slog.New(slog.DiscardHandler),
	}
	e.opts = app.SignInOptions{
		Clients: signInClients, FlowTTL: 10 * time.Minute, IdleTTL: 168 * time.Hour, AbsoluteTTL: 720 * time.Hour,
		KnownDeviceWindow: 90 * 24 * time.Hour, RestrictedSignIn: true,
		Throttle: account.ThrottlePolicy{Threshold: 5, FirstDelay: time.Second, MaxDelay: 15 * time.Minute},
	}
	if e.signIn, err = app.NewSignIn(e.deps, e.opts); err != nil {
		t.Fatal(err)
	}
	return e
}

// rebuild makes the use case again after a change to e.opts.
func (e *signEnv) rebuild(t *testing.T) {
	t.Helper()
	var err error
	if e.signIn, err = app.NewSignIn(e.deps, e.opts); err != nil {
		t.Fatal(err)
	}
}

func signCmd(client, password string) app.SignInPassword {
	return app.SignInPassword{ClientID: client, Type: "email", Value: " Ada@Example.org ", Password: flow.Secret(password),
		UserAgent: "Mozilla/5.0 (test)", IP: signInIP}
}

func (e *signEnv) run(t *testing.T, cmd app.SignInPassword) (app.SignInResult, error) {
	t.Helper()
	return e.signIn.Password(t.Context(), cmd)
}

// fail signs in with a wrong password n times.
func (e *signEnv) fail(t *testing.T, cmd app.SignInPassword, n int) {
	t.Helper()
	cmd.Password = flow.Secret("wrong password")
	for i := range n {
		if _, err := e.run(t, cmd); !hasDomainCode(err, domain.CodeInvalidCredentials) {
			t.Fatalf("wrong password %d: %v, want INVALID_CREDENTIALS", i+1, err)
		}
	}
}

func (e *signEnv) setStatus(s account.Status) {
	a := e.accounts.accounts[e.accountID]
	a.Status = s
	e.accounts.accounts[e.accountID] = a
}

func (e *signEnv) confirmTOTP() {
	t := now.Add(-time.Hour)
	e.accounts.totp[e.accountID] = account.TOTPFactor{Secret: []byte("secret"), ConfirmedAt: &t}
}

func TestNewSignInRefusesMissing(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	d := e.deps
	d.Throttles, d.Access = nil, nil
	if _, err := app.NewSignIn(d, e.opts); err == nil || !strings.Contains(err.Error(), "Throttles, Access") {
		t.Errorf("NewSignIn without Throttles and Access = %v", err)
	}
	o := e.opts
	o.AbsoluteTTL = 0
	if _, err := app.NewSignIn(e.deps, o); err == nil {
		t.Error("NewSignIn with no absolute TTL accepted")
	}
}

// TestSignInChecksInOrder checks the refusals that come before any hashing (TDD-07 §2).
func TestSignInChecksInOrder(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		cmd   func(*signEnv) app.SignInPassword
		code  domain.Code
		field string
	}{
		{"unknown client", func(*signEnv) app.SignInPassword { return signCmd("nobody", signInPassword) },
			domain.CodeValidationFailed, "client_id"},
		{"password not a first factor", func(*signEnv) app.SignInPassword { return signCmd("otp", signInPassword) },
			domain.CodeValidationFailed, "client_id"},
		{"type not a sign-in type", func(*signEnv) app.SignInPassword {
			c := signCmd("web", signInPassword)
			c.Type, c.Value = "phone", "+44 7400 123456"
			return c
		}, domain.CodeValidationFailed, "identifier.type"},
		{"unknown type", func(*signEnv) app.SignInPassword {
			c := signCmd("web", signInPassword)
			c.Type = "fax"
			return c
		}, domain.CodeValidationFailed, "identifier.type"},
		{"L-2", func(e *signEnv) app.SignInPassword {
			for range 30 {
				_, _ = e.run(t, app.SignInPassword{ClientID: "web", Type: "email", Value: "x@example.org", IP: signInIP})
			}
			e.hasher.dummies = 0
			return signCmd("web", signInPassword)
		}, domain.CodeRateLimited, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newSignInEnv(t, false)
			_, err := e.run(t, tt.cmd(e))
			de := asCode(t, err, tt.code)
			if tt.field != "" && (len(de.Fields) != 1 || de.Fields[0].Field != tt.field) {
				t.Errorf("fields %v, want %s", de.Fields, tt.field)
			}
			if e.hasher.verifies+e.hasher.dummies+e.hasher.hashes != 0 {
				t.Error("hashed before the refusal")
			}
		})
	}
}

// TestSignInUnknownVerifiesDummy checks an unknown identifier costs one dummy verification and
// answers as a wrong password (TDD-03 §1.4 step 4).
func TestSignInUnknownVerifiesDummy(t *testing.T) {
	t.Parallel()
	for name, value := range map[string]string{
		"unknown":            "nobody@example.org",
		"does not normalise": "not an address",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newSignInEnv(t, false)
			c := signCmd("web", signInPassword)
			c.Value = value
			_, err := e.run(t, c)
			wantCode(t, err, domain.CodeInvalidCredentials)
			if e.hasher.dummies != 1 || e.hasher.verifies != 0 {
				t.Errorf("dummies %d, verifies %d; want 1, 0", e.hasher.dummies, e.hasher.verifies)
			}
			if len(e.throttles.failures) != 0 || len(e.accounts.locked) != 0 {
				t.Error("an unknown identifier counted a failure or locked an account")
			}
			if len(e.audit.entries) != 1 || e.audit.entries[0].Outcome != app.OutcomeFailure {
				t.Errorf("audit %v, want one failure", e.audit.entries)
			}
		})
	}
}

func TestSignInWrongPasswordCountsBucket(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	e.fail(t, signCmd("web", signInPassword), 2)
	if got := e.throttles.failures[bucketKey(e.accountID, account.UntrustedBucket)]; got != 2 {
		t.Errorf("untrusted failures %d, want 2", got)
	}
	if len(e.accounts.locked) != 0 {
		t.Error("a failure locked the account (it must move no version)")
	}
	if len(e.sessions.created) != 0 {
		t.Error("a wrong password created a session")
	}
}

// TestSignInDelayedRefusesBeforeVerify is L-3: from the 5th failure the bucket waits.
func TestSignInDelayedRefusesBeforeVerify(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	e.fail(t, signCmd("web", signInPassword), 5)
	e.clock.Advance(time.Second)
	e.fail(t, signCmd("web", signInPassword), 1) // the 6th: 2 s from now
	verifies := e.hasher.verifies
	e.clock.Advance(500 * time.Millisecond)
	_, err := e.run(t, signCmd("web", signInPassword))
	de := asCode(t, err, domain.CodeSignInDelayed)
	if de.RetryAfter != 2*time.Second {
		t.Errorf("RetryAfter %v, want 2s (1.5 s left, rounded up)", de.RetryAfter)
	}
	if e.hasher.verifies != verifies {
		t.Error("a delayed sign-in verified the password")
	}
	e.clock.Advance(2 * time.Second)
	if res, err := e.run(t, signCmd("web", signInPassword)); err != nil || res.Tokens == nil {
		t.Fatalf("after the delay: %v, %v", res, err)
	}
	if got := e.throttles.failures[bucketKey(e.accountID, account.UntrustedBucket)]; got != 0 {
		t.Errorf("failures after a success = %d, want the bucket reset", got)
	}
}

// TestSignInFailOpenRedis is T-16 in the use case: with the limiter failing, L-2 lets requests
// through, and the PostgreSQL delay still holds.
func TestSignInFailOpenRedis(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	e.limiter.Fail(errors.New("redis down"))
	e.fail(t, signCmd("web", signInPassword), 5)
	_, err := e.run(t, signCmd("web", signInPassword))
	wantCode(t, err, domain.CodeSignInDelayed)
}

// TestSignInStatusRows are the sign-in cells of SDD §8.1.
func TestSignInStatusRows(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		status     account.Status
		restricted bool // statuses.restricted_sign_in
		code       domain.Code
		token      string // "full" or "restricted" when it signs in
	}{
		{account.StatusPending, true, domain.CodeRegistrationIncomplete, ""},
		{account.StatusActive, true, "", "full"},
		{account.StatusSuspended, true, "", "restricted"},
		{account.StatusBanned, true, "", "restricted"},
		{account.StatusSuspended, false, domain.CodeAccountRestricted, ""},
		{account.StatusBanned, false, domain.CodeAccountRestricted, ""},
		{account.StatusDeleted, true, domain.CodeInvalidCredentials, ""},
	} {
		t.Run(fmt.Sprintf("%s restricted_sign_in %t", tt.status, tt.restricted), func(t *testing.T) {
			t.Parallel()
			e := newSignInEnv(t, false)
			e.opts.RestrictedSignIn = tt.restricted
			e.rebuild(t)
			e.setStatus(tt.status)
			res, err := e.run(t, signCmd("web", signInPassword))
			if tt.code != "" {
				wantCode(t, err, tt.code)
				if len(e.sessions.created) != 0 {
					t.Error("a refused sign-in created a session")
				}
				return
			}
			if err != nil || res.Tokens == nil {
				t.Fatalf("Password = %v, %v", res, err)
			}
			if got := res.Tokens.Access.Restricted; got != (tt.token == "restricted") {
				t.Errorf("restricted token %v, want %s", got, tt.token)
			}
			if res.Tokens.Status != tt.status {
				t.Errorf("status %s, want %s", res.Tokens.Status, tt.status)
			}
		})
	}
	t.Run("pending, wrong password", func(t *testing.T) {
		t.Parallel()
		e := newSignInEnv(t, false)
		e.setStatus(account.StatusPending)
		e.fail(t, signCmd("web", signInPassword), 1)
	})
}

func TestSignInRoleNotPermitted(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	_, err := e.run(t, signCmd("admin", signInPassword))
	wantCode(t, err, domain.CodeRoleNotPermitted)
	if len(e.sessions.created) != 0 || len(e.flows.opened) != 0 {
		t.Error("a role refusal created a session or a flow")
	}
}

// TestT30SecondStep is TDD-03 §3.4's table (T-30, I-16).
func TestT30SecondStep(t *testing.T) {
	t.Parallel()
	t.Run("optional client, no TOTP: tokens with amr pwd", func(t *testing.T) {
		t.Parallel()
		e := newSignInEnv(t, false)
		res, err := e.run(t, signCmd("web", signInPassword))
		if err != nil || res.Tokens == nil || res.Step != nil {
			t.Fatalf("Password = %+v, %v; want tokens", res, err)
		}
		if got := e.sessions.created[0].AMR; !slices.Equal(got, []string{"pwd"}) {
			t.Errorf("session amr %v, want [pwd]", got)
		}
		if got := e.access.grants[0].AMR; !slices.Equal(got, []string{"pwd"}) {
			t.Errorf("token amr %v, want [pwd]", got)
		}
		if len(e.flows.opened) != 0 {
			t.Errorf("flows opened %v, want none on the optional path", e.flows.opened)
		}
	})
	t.Run("an unconfirmed TOTP counts as none", func(t *testing.T) {
		t.Parallel()
		e := newSignInEnv(t, false)
		e.accounts.totp[e.accountID] = account.TOTPFactor{Secret: []byte("pending")}
		if res, err := e.run(t, signCmd("web", signInPassword)); err != nil || res.Tokens == nil {
			t.Fatalf("Password = %+v, %v; want tokens", res, err)
		}
	})
	for _, tt := range []struct {
		name   string
		client string
		totp   bool
		code   app.StepCode
		step   flow.Step
	}{
		{"TOTP, optional client", "web", true, app.StepMFARequired, flow.StepSecondFactor},
		{"TOTP, required client", "secure", true, app.StepMFARequired, flow.StepSecondFactor},
		{"no TOTP, required client", "secure", false, app.StepMFAEnrolmentRequired, flow.StepEnrolment},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newSignInEnv(t, false)
			if tt.totp {
				e.confirmTOTP()
			}
			res, err := e.run(t, signCmd(tt.client, signInPassword))
			if err != nil || res.Step == nil || res.Tokens != nil {
				t.Fatalf("Password = %+v, %v; want a step", res, err)
			}
			if len(e.sessions.created) != 0 {
				t.Fatal("a session before the second step (I-16)")
			}
			s := res.Step
			if s.Code != tt.code || len(s.Handle) != 43 || !s.ExpiresAt.Equal(now.Add(10*time.Minute)) {
				t.Errorf("step %v %d-character handle, expires %v", s.Code, len(s.Handle), s.ExpiresAt)
			}
			f := e.flows.opened[0]
			h := sha256.Sum256(s.Handle)
			if f.ID != s.FlowID || f.Kind != flow.KindSignIn || f.ClientID != tt.client || !bytes.Equal(f.HandleHash, h[:]) {
				t.Errorf("flow %+v", f)
			}
			st, ok := f.State.(flow.SignInState)
			if !ok || st.FirstFactor != flow.FirstFactorPassword || st.Step != tt.step || st.DeviceID != nil {
				t.Errorf("flow state %+v, want pwd at %s, no device", f.State, tt.step)
			}
			if !slices.Equal(e.throttles.resets, []account.Bucket{account.UntrustedBucket}) {
				t.Errorf("resets %v, want the bucket reset at the first factor", e.throttles.resets)
			}
		})
	}
}

// TestSignInReChecksUnderLock changes what the first factor read before the transaction locks
// the account (TDD-02 §5.1 step 8).
func TestSignInReChecksUnderLock(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		change func(*signEnv)
		code   domain.Code
		token  string
	}{
		{"password changed", func(e *signEnv) {
			e.accounts.creds[e.accountID] = account.PasswordCredential{Hash: "phc:another", PepperKID: "1"}
		}, domain.CodeInvalidCredentials, ""},
		{"pepper key changed", func(e *signEnv) {
			e.accounts.creds[e.accountID] = account.PasswordCredential{Hash: "phc:" + signInPassword, PepperKID: "2"}
		}, domain.CodeInvalidCredentials, ""},
		{"identifier retired", func(e *signEnv) { delete(e.accounts.verified, "email:"+signInEmail) },
			domain.CodeInvalidCredentials, ""},
		{"identifier moved to another account", func(e *signEnv) {
			id := e.accounts.verified["email:"+signInEmail]
			id.AccountID = fakes.ID(99)
			e.accounts.verified["email:"+signInEmail] = id
		}, domain.CodeInvalidCredentials, ""},
		{"now suspended", func(e *signEnv) { e.setStatus(account.StatusSuspended) }, "", "restricted"},
		{"now deleted", func(e *signEnv) { e.setStatus(account.StatusDeleted) }, domain.CodeInvalidCredentials, ""},
		{"role removed", func(e *signEnv) { e.accounts.roles[e.accountID] = []string{"admin"} },
			domain.CodeRoleNotPermitted, ""},
		{"TOTP confirmed", func(e *signEnv) { e.confirmTOTP() }, "", "step"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newSignInEnv(t, false)
			e.accounts.beforeLock = func() { tt.change(e) }
			res, err := e.run(t, signCmd("web", signInPassword))
			switch tt.token {
			case "":
				wantCode(t, err, tt.code)
				if len(e.sessions.created)+len(e.flows.opened) != 0 {
					t.Error("a refusal under the lock created a session or a flow")
				}
				if len(e.throttles.failures) != 0 {
					t.Error("a refusal under the lock counted a failure")
				}
				if last := e.audit.entries[len(e.audit.entries)-1]; last.Outcome != app.OutcomeFailure {
					t.Errorf("last audit entry %v, want the failure", last)
				}
			case "restricted":
				if err != nil || res.Tokens == nil || !res.Tokens.Access.Restricted {
					t.Errorf("Password = %+v, %v; want a restricted session", res, err)
				}
			case "step":
				if err != nil || res.Step == nil || res.Step.Code != app.StepMFARequired {
					t.Errorf("Password = %+v, %v; want MFA_REQUIRED", res, err)
				}
			}
		})
	}
}

func TestSignInRehash(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	e.accounts.creds[e.accountID] = account.PasswordCredential{Hash: "phc:" + signInPassword, PepperKID: "0"}
	if res, err := e.run(t, signCmd("web", signInPassword)); err != nil || res.Tokens == nil {
		t.Fatalf("Password = %+v, %v", res, err)
	}
	if e.hasher.hashes != 1 || len(e.accounts.rehashed) != 1 {
		t.Errorf("hashes %d, rehashed %v; want one rehash", e.hasher.hashes, e.accounts.rehashed)
	}
	if got := e.accounts.creds[e.accountID].PepperKID; got != "1" {
		t.Errorf("pepper key after rehash %q, want 1", got)
	}

	// A stored hash that changes between the verification and the lock is not overwritten: the
	// re-check refuses the sign-in first.
	e = newSignInEnv(t, false)
	e.accounts.creds[e.accountID] = account.PasswordCredential{Hash: "phc:" + signInPassword, PepperKID: "0"}
	e.accounts.beforeLock = func() {
		e.accounts.creds[e.accountID] = account.PasswordCredential{Hash: "phc:changed", PepperKID: "1"}
	}
	_, err := e.run(t, signCmd("web", signInPassword))
	wantCode(t, err, domain.CodeInvalidCredentials)
	if got := e.accounts.creds[e.accountID].Hash; got != "phc:changed" {
		t.Errorf("hash %q, want the changed password kept", got)
	}
}

// TestSignInDeviceBuckets is T-34 in the use case: a known device has a bucket of its own.
func TestSignInDeviceBuckets(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	res, err := e.run(t, signCmd("web", signInPassword))
	if err != nil || res.Tokens == nil || res.Tokens.DeviceCookie == "" {
		t.Fatalf("first sign-in = %+v, %v; want a device cookie", res, err)
	}
	cookie := res.Tokens.DeviceCookie
	device := *e.sessions.created[0].DeviceID
	if id, ok := e.devices.Parse(cookie); !ok || id != device {
		t.Fatalf("cookie for %v, session device %v", id, device)
	}
	e.throttles.known[e.accountID.String()+":"+device.String()] = true

	e.fail(t, signCmd("web", signInPassword), 5) // an attacker, with no cookie
	_, err = e.run(t, signCmd("web", signInPassword))
	wantCode(t, err, domain.CodeSignInDelayed)

	withCookie := signCmd("web", signInPassword)
	withCookie.DeviceCookie = cookie
	res, err = e.run(t, withCookie)
	if err != nil || res.Tokens == nil {
		t.Fatalf("the known device: %v, %v; want tokens", res, err)
	}
	if res.Tokens.DeviceCookie != "" {
		t.Error("a new device cookie for a browser that presented a valid one")
	}
	if got := *e.sessions.created[1].DeviceID; got != device {
		t.Errorf("session device %v, want the cookie's %v", got, device)
	}
	if !slices.Equal(e.throttles.resets[1:], []account.Bucket{account.DeviceBucket(device)}) {
		t.Errorf("resets %v, want the device bucket", e.throttles.resets)
	}

	// A valid cookie of a device the account has never seen counts as untrusted, and is kept.
	e2 := newSignInEnv(t, false)
	e2.fail(t, signCmd("web", signInPassword), 5)
	stranger := signCmd("web", signInPassword)
	stranger.DeviceCookie, _ = e2.devices.Issue()
	_, err = e2.run(t, stranger)
	wantCode(t, err, domain.CodeSignInDelayed)

	// An invalid cookie counts as none, and a new one is set.
	e3 := newSignInEnv(t, false)
	bad := signCmd("web", signInPassword)
	bad.DeviceCookie = "not a cookie"
	if res, err := e3.run(t, bad); err != nil || res.Tokens == nil || res.Tokens.DeviceCookie == "" {
		t.Errorf("invalid cookie: %+v, %v; want a new cookie", res, err)
	}
}

// TestSignInDeviceOnFlow checks a valid cookie presented at the first factor is kept in the
// sign-in flow, for the session WP-53 and WP-54 create.
func TestSignInDeviceOnFlow(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	e.confirmTOTP()
	c := signCmd("web", signInPassword)
	var device uuid.UUID
	c.DeviceCookie, device = e.devices.Issue()
	if _, err := e.run(t, c); err != nil {
		t.Fatal(err)
	}
	st := e.flows.opened[0].State.(flow.SignInState)
	if st.DeviceID == nil || *st.DeviceID != device {
		t.Errorf("flow device %v, want %v", st.DeviceID, device)
	}
}

func TestSignInNativeClientUntrusted(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	c := signCmd("native", signInPassword)
	var device uuid.UUID
	c.DeviceCookie, device = e.devices.Issue()
	e.throttles.known[e.accountID.String()+":"+device.String()] = true
	res, err := e.run(t, c)
	if err != nil || res.Tokens == nil {
		t.Fatalf("Password = %+v, %v", res, err)
	}
	if !res.Tokens.BodyTransport || res.Tokens.DeviceCookie != "" || e.sessions.created[0].DeviceID != nil {
		t.Errorf("native sign-in: body %v, cookie %q, device %v; want body, none, none",
			res.Tokens.BodyTransport, res.Tokens.DeviceCookie, e.sessions.created[0].DeviceID)
	}
	if !slices.Equal(e.throttles.resets, []account.Bucket{account.UntrustedBucket}) {
		t.Errorf("resets %v, want untrusted", e.throttles.resets)
	}
}

func TestSignInSession(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	c := signCmd("web", signInPassword)
	c.UserAgent = strings.Repeat("é", 400) // 800 bytes
	res, err := e.run(t, c)
	if err != nil {
		t.Fatal(err)
	}
	s := e.sessions.created[0]
	tok := res.Tokens
	if s.ID != tok.SessionID || s.AccountID != e.accountID || s.ClientID != "web" || !s.AuthTime.Equal(now) {
		t.Errorf("session %+v", s)
	}
	if s.IdleTTL != 168*time.Hour || s.AbsoluteTTL != 720*time.Hour || tok.RefreshMaxAge != 720*time.Hour {
		t.Errorf("idle %v, absolute %v, cookie max age %v", s.IdleTTL, s.AbsoluteTTL, tok.RefreshMaxAge)
	}
	if len(s.UserAgent) > 512 || !strings.HasPrefix(c.UserAgent, s.UserAgent) || len(s.UserAgent) < 510 {
		t.Errorf("user agent cut to %d bytes", len(s.UserAgent))
	}
	h := sha256.Sum256(tok.Refresh)
	if len(tok.Refresh) != 43 || !bytes.Equal(e.sessions.hashes[0], h[:]) {
		t.Errorf("refresh token %d characters; stored hash matches %v", len(tok.Refresh), bytes.Equal(e.sessions.hashes[0], h[:]))
	}
	if tok.Access.Token != "jwt:"+s.ID.String() || tok.ExpiresIn != 15*time.Minute {
		t.Errorf("access %v, expires in %v", tok.Access, tok.ExpiresIn)
	}
	g := e.access.grants[0]
	if g.Audience != "https://web.example.com" || !slices.Equal(g.Roles, []string{"member"}) {
		t.Errorf("grant %+v", g)
	}
	last := e.audit.entries[len(e.audit.entries)-1]
	if last.Action != "sign_in" || last.Outcome != app.OutcomeSuccess || last.AccountID != e.accountID {
		t.Errorf("last audit entry %+v, want the sign_in success", last)
	}
}

// TestSignInNotice is the optional new-sign-in notice (TDD-06 §7).
func TestSignInNotice(t *testing.T) {
	t.Parallel()
	for _, on := range []bool{false, true} {
		e := newSignInEnv(t, on)
		if _, err := e.run(t, signCmd("web", signInPassword)); err != nil {
			t.Fatal(err)
		}
		if !on {
			if len(e.outbox.requests) != 0 {
				t.Errorf("off: %d delivery requests, want none", len(e.outbox.requests))
			}
			continue
		}
		if len(e.outbox.requests) != 1 {
			t.Fatalf("on: %d delivery requests, want 1", len(e.outbox.requests))
		}
		r := e.outbox.requests[0]
		want := map[string]any{"client_id": "web", "user_agent": "Mozilla/5.0 (test)", "occurred_at": now.Format(time.RFC3339)}
		if r.Type != "auth.notice_new_sign_in" || fmt.Sprint(r.Variables) != fmt.Sprint(want) {
			t.Errorf("request %s %v, want auth.notice_new_sign_in %v", r.Type, r.Variables, want)
		}
	}
}

// TestCompleteRefusesWithoutMFA is I-16's guard: Complete never creates a session without mfa
// in its amr for an account with a confirmed TOTP or on a required client.
func TestCompleteRefusesWithoutMFA(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		client string
		totp   bool
	}{
		{"confirmed TOTP", "web", true},
		{"required client", "secure", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newSignInEnv(t, false)
			if tt.totp {
				e.confirmTOTP()
			}
			err := e.uow.Do(t.Context(), func(ctx context.Context) error {
				a, err := e.accounts.GetForUpdate(ctx, e.accountID)
				if err != nil {
					return err
				}
				_, err = e.signIn.Complete(ctx, app.Completion{Account: a, ClientID: tt.client,
					First: flow.FirstFactorPassword, Second: flow.SecondNone})
				return err
			})
			if !errors.Is(err, app.ErrMFANotPassed) {
				t.Errorf("Complete = %v, want ErrMFANotPassed", err)
			}
			if len(e.sessions.created) != 0 {
				t.Error("a session without mfa (I-16)")
			}
		})
	}
}

func TestCompleteWithFlow(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	e.confirmTOTP()
	device := fakes.ID(77)
	f := &flow.Flow{ID: fakes.ID(50), Kind: flow.KindSignIn, AccountID: e.accountID, ClientID: "web",
		State: flow.SignInState{FirstFactor: flow.FirstFactorPassword, Step: flow.StepSecondFactor, DeviceID: &device}}
	var got app.SignedIn
	if err := e.uow.Do(t.Context(), func(ctx context.Context) error {
		a, err := e.accounts.GetForUpdate(ctx, e.accountID)
		if err != nil {
			return err
		}
		got, err = e.signIn.Complete(ctx, app.Completion{Account: a, ClientID: "web", Flow: f,
			First: flow.FirstFactorPassword, Second: flow.SecondTOTP, DeviceID: &device})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(e.flows.completed, []uuid.UUID{f.ID}) {
		t.Errorf("completed %v, want the flow", e.flows.completed)
	}
	if amr := e.sessions.created[0].AMR; !slices.Equal(amr, []string{"pwd", "otp", "mfa"}) {
		t.Errorf("amr %v", amr)
	}
	if got.DeviceCookie != "" || *e.sessions.created[0].DeviceID != device {
		t.Errorf("cookie %q, session device %v; want no new cookie, the flow's device", got.DeviceCookie,
			e.sessions.created[0].DeviceID)
	}
}

// TestSignInAuditHoldsNoValue checks no audit entry or error holds the identifier value, the
// password or a token (G-6).
func TestSignInAuditHoldsNoValue(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, true)
	var texts []string
	for _, c := range []app.SignInPassword{signCmd("web", "wrong password"), signCmd("web", signInPassword)} {
		res, err := e.run(t, c)
		if err != nil {
			texts = append(texts, err.Error())
		}
		texts = append(texts, fmt.Sprint(res), fmt.Sprintf("%+v %#v", c, c))
		if res.Tokens != nil {
			texts = append(texts, fmt.Sprintf("%v %+v", *res.Tokens, *res.Tokens))
		}
	}
	for _, en := range e.audit.entries {
		texts = append(texts, fmt.Sprintf("%+v", en))
	}
	for _, s := range texts {
		for _, secret := range []string{signInEmail, "Ada@Example", signInPassword, "wrong password", "jwt:"} {
			if strings.Contains(s, secret) {
				t.Errorf("%q holds %q", s, secret)
			}
		}
	}
}

func TestSignInOverloaded(t *testing.T) {
	t.Parallel()
	e := newSignInEnv(t, false)
	e.hasher.err = app.ErrOverloaded
	_, err := e.run(t, signCmd("web", signInPassword))
	if de := asCode(t, err, domain.CodeUnavailable); de.RetryAfter != time.Second {
		t.Errorf("RetryAfter %v, want 1s", de.RetryAfter)
	}
	if len(e.throttles.failures) != 0 {
		t.Error("an overloaded verify counted a failure")
	}
}
