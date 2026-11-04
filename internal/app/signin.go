package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/identifier"
)

// SignInClient is what sign-in needs of a configured client (SDD D-6).
type SignInClient struct {
	ID            string
	Audience      string
	AllowedRoles  []string
	Password      bool // password is in first_factors
	MFARequired   bool // mfa: required
	BodyTransport bool // refresh_transport: body (a native client)
}

// SignInOptions are the sign-in settings from configuration.
type SignInOptions struct {
	// Clients are the configured clients, by id.
	Clients map[string]SignInClient
	// FlowTTL is flows.sign_in_flow_ttl, IdleTTL and AbsoluteTTL are tokens.refresh_idle_ttl and
	// tokens.refresh_absolute_ttl; each above 0.
	FlowTTL, IdleTTL, AbsoluteTTL time.Duration
	// KnownDeviceWindow is how long after its last session ended a device stays known (TDD-07 §4:
	// 90 days); above 0.
	KnownDeviceWindow time.Duration
	// RestrictedSignIn is statuses.restricted_sign_in.
	RestrictedSignIn bool
	// Throttle is rate_limits.sign_in_failures (L-3).
	Throttle account.ThrottlePolicy
}

// SignInDeps are the ports and components the sign-in uses. Every field is required.
type SignInDeps struct {
	UnitOfWork UnitOfWork
	Accounts   Accounts
	Flows      Flows
	Sessions   Sessions
	Throttles  SignInThrottles
	Notices    *Notices
	Audit      AuditWriter
	Hasher     PasswordHasher
	Registry   *identifier.Registry
	Limits     *RateLimits
	Access     AccessIssuer
	Devices    *DeviceCookies
	IDs        IDGenerator
	Clock      Clock
	Rand       io.Reader // crypto/rand.Reader outside tests
	Logger     *slog.Logger
}

// missing returns the names of the fields of d that are nil.
func (d SignInDeps) missing() []string {
	fields := []struct {
		name string
		nil  bool
	}{
		{"UnitOfWork", d.UnitOfWork == nil}, {"Accounts", d.Accounts == nil}, {"Flows", d.Flows == nil},
		{"Sessions", d.Sessions == nil}, {"Throttles", d.Throttles == nil}, {"Notices", d.Notices == nil},
		{"Audit", d.Audit == nil}, {"Hasher", d.Hasher == nil}, {"Registry", d.Registry == nil},
		{"Limits", d.Limits == nil}, {"Access", d.Access == nil}, {"Devices", d.Devices == nil},
		{"IDs", d.IDs == nil}, {"Clock", d.Clock == nil}, {"Rand", d.Rand == nil}, {"Logger", d.Logger == nil},
	}
	var out []string
	for _, f := range fields {
		if f.nil {
			out = append(out, f.name)
		}
	}
	return out
}

// SignIn is the password sign-in (TDD-02 §5.1) and the completion of every sign-in (§5.3). The
// password is verified, and rehashed, outside any transaction (G-4); then one transaction locks
// the account, decides again on what it reads under the lock, and opens the sign_in flow of a
// second step or completes the sign-in. No identifier value, password, handle, token or cookie
// goes into an error, an event or an audit entry (G-6).
type SignIn struct {
	d SignInDeps
	o SignInOptions
}

// NewSignIn returns the sign-in, or an error naming the missing dependencies or the bad option.
// It keeps its own copy of the options' clients.
func NewSignIn(d SignInDeps, o SignInOptions) (*SignIn, error) {
	if m := d.missing(); len(m) > 0 {
		return nil, fmt.Errorf("sign-in: missing %s", strings.Join(m, ", "))
	}
	if o.FlowTTL <= 0 || o.IdleTTL <= 0 || o.AbsoluteTTL <= 0 || o.KnownDeviceWindow <= 0 {
		return nil, errors.New("sign-in: the flow, refresh and known-device lifetimes must be above 0")
	}
	o.Clients = maps.Clone(o.Clients)
	return &SignIn{d: d, o: o}, nil
}

// The audit actions of the sign-in.
const (
	auditSignInPassword = "sign_in.password" // the first factor, a password
	auditSignIn         = "sign_in"          // a completed sign-in (TDD-02 §5.3)
)

// SignInPassword is a sign-in with a password (POST /v1/sessions). It formats and logs as its
// client and identifier type only: never the value, the password or the device cookie.
type SignInPassword struct {
	ClientID     string
	Type         string
	Value        string // raw, as typed
	Password     flow.Secret
	DeviceCookie string // the __Host-auth1_dev cookie's value, if any
	UserAgent    string
	IP           netip.Addr
}

// String describes the request without its personal or secret fields.
func (c SignInPassword) String() string {
	return fmt.Sprintf("SignInPassword{client: %s, type: %s}", c.ClientID, c.Type)
}

// GoString is String.
func (c SignInPassword) GoString() string { return c.String() }

// Format writes String for every verb.
func (c SignInPassword) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }

// LogValue implements slog.LogValuer with String.
func (c SignInPassword) LogValue() slog.Value { return slog.StringValue(c.String()) }

// StepCode is the second step a sign-in continues with (TDD-03 §3.4). It is not an error.
type StepCode string

// The second steps.
const (
	StepMFARequired          StepCode = "MFA_REQUIRED"           // give a TOTP or recovery code
	StepMFAEnrolmentRequired StepCode = "MFA_ENROLMENT_REQUIRED" // enrol TOTP first (TDD-03 §4.1)
)

// SignInStep is a sign-in waiting for its second step: the sign_in flow, its handle (returned
// once, stored as its SHA-256) and when it expires.
type SignInStep struct {
	Code      StepCode
	FlowID    uuid.UUID
	Handle    flow.Secret
	ExpiresAt time.Time
}

// SignInResult is a sign-in's answer: tokens, or a second step. Exactly one is set.
type SignInResult struct {
	Tokens *SignedIn
	Step   *SignInStep
}

// Password signs in with a password (TDD-02 §5.1). Before any hashing: the client and the
// identifier type, then L-2. An identifier that matches no verified one costs a dummy
// verification and answers INVALID_CREDENTIALS, like a wrong password. A delayed bucket answers
// SIGN_IN_DELAYED without verifying. A wrong password counts in the bucket, in a transaction that
// locks no account. A correct one is decided by SDD §8.1 and the client's roles, on an unlocked
// read, and again under the account lock in the transaction that resets the bucket, writes a
// rehash, and opens the sign_in flow of a second step or completes the sign-in.
func (s *SignIn) Password(ctx context.Context, cmd SignInPassword) (SignInResult, error) {
	const op = "sign in"
	ua := userAgent(cmd.UserAgent)
	entry := AuditEntry{ActorKind: ActorAnonymous, Action: auditSignInPassword, ClientID: cmd.ClientID,
		IP: cmd.IP, UserAgent: ua}
	c, ok := s.o.Clients[cmd.ClientID]
	if !ok {
		return SignInResult{}, s.fail(ctx, entry, op, invalidField("client_id", domain.FieldUnknown))
	}
	if !c.Password {
		return SignInResult{}, s.fail(ctx, entry, op, invalidField("client_id", domain.FieldNotAllowed))
	}
	if p, ok := s.d.Registry.Policy(cmd.Type); !ok || !p.SignIn {
		return SignInResult{}, s.fail(ctx, entry, op, invalidField("identifier.type", domain.FieldNotAllowed))
	}
	if err := s.d.Limits.CheckIP(ctx, RuleSignInIP, cmd.IP); err != nil {
		return SignInResult{}, err // not audited: the per-IP limits bound the volume, not audit rows
	}

	value, err := s.d.Registry.Normalise(cmd.Type, cmd.Value)
	if err != nil {
		return SignInResult{}, s.unknown(ctx, entry, op, cmd.Password)
	}
	id, err := s.d.Accounts.FindVerified(ctx, cmd.Type, value)
	if hasCode(err, domain.CodeNotFound) {
		return SignInResult{}, s.unknown(ctx, entry, op, cmd.Password)
	} else if err != nil {
		return SignInResult{}, fmt.Errorf("%s: %w", op, err)
	}
	a, err := s.d.Accounts.Get(ctx, id.AccountID)
	if err != nil {
		return SignInResult{}, fmt.Errorf("%s: %w", op, err)
	}
	cred, err := s.d.Accounts.PasswordCredential(ctx, a.ID)
	if hasCode(err, domain.CodeNotFound) {
		return SignInResult{}, s.unknown(ctx, entry, op, cmd.Password) // a deleted account's was erased
	} else if err != nil {
		return SignInResult{}, fmt.Errorf("%s: %w", op, err)
	}
	entry.AccountID = a.ID

	device, bucket, err := s.bucket(ctx, c, a.ID, cmd.DeviceCookie)
	if err != nil {
		return SignInResult{}, fmt.Errorf("%s: %w", op, err)
	}
	entry.Details = map[string]any{"bucket": bucketKind(bucket)}
	delay, err := s.d.Throttles.Delay(ctx, a.ID, bucket)
	if err != nil {
		return SignInResult{}, fmt.Errorf("%s: %w", op, err)
	}
	if delay > 0 {
		return SignInResult{}, s.fail(ctx, entry, op, &domain.Error{Code: domain.CodeSignInDelayed,
			Detail: "too many failed sign-ins; try again later", RetryAfter: ceilSecond(delay)})
	}

	ok, needsRehash, err := s.d.Hasher.Verify(ctx, cred.Hash, cred.PepperKID, cmd.Password)
	if err != nil {
		return SignInResult{}, s.fail(ctx, entry, op, err)
	}
	if !ok {
		return SignInResult{}, s.wrongPassword(ctx, entry, op, a.ID, bucket)
	}
	if answer, err := s.decide(ctx, a, c); err != nil || answer != nil {
		return SignInResult{}, s.settle(ctx, entry, op, err, answer)
	}
	var rehash, rehashKID string
	if needsRehash {
		if rehash, rehashKID, err = s.d.Hasher.Hash(ctx, cmd.Password); err != nil {
			// The sign-in stands; the next one rehashes.
			s.d.Logger.LogAttrs(ctx, slog.LevelWarn, "password rehash skipped", slog.String("error", err.Error()))
			rehash = ""
		}
	}
	handle, err := flow.NewHandle(s.d.Rand)
	if err != nil {
		return SignInResult{}, fmt.Errorf("%s: %w", op, err)
	}

	var (
		res    SignInResult
		answer error
	)
	err = s.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		la, err := s.d.Accounts.GetForUpdate(ctx, a.ID)
		if err != nil {
			return err
		}
		if answer, err = s.recheck(ctx, la, c, cmd.Type, value, cred); err != nil || answer != nil {
			return err
		}
		if err := s.d.Throttles.Reset(ctx, la.ID, bucket); err != nil {
			return err
		}
		if rehash != "" {
			if _, err := s.d.Accounts.RehashPassword(ctx, la.ID, cred.Hash, rehash, rehashKID); err != nil {
				return err
			}
		}
		code, err := s.secondStep(ctx, la.ID, c)
		if err != nil {
			return err
		}
		if code == "" {
			signed, err := s.Complete(ctx, Completion{Account: la, ClientID: c.ID, First: flow.FirstFactorPassword,
				Second: flow.SecondNone, DeviceID: device, UserAgent: cmd.UserAgent, IP: cmd.IP})
			if err != nil {
				return err
			}
			res.Tokens = &signed
			return nil
		}
		step, err := s.openStep(ctx, la.ID, c.ID, code, device, handle)
		if err != nil {
			return err
		}
		res.Step = &step
		entry.Outcome = OutcomeSuccess
		entry.Details["flow_id"], entry.Details["kind"], entry.Details["step"] = step.FlowID.String(),
			string(flow.KindSignIn), string(code)
		return s.d.Audit.Write(ctx, entry)
	})
	if err := s.settle(ctx, entry, op, err, answer); err != nil {
		return SignInResult{}, err
	}
	return res, nil
}

// bucket returns the device of a valid device cookie, nil without one, and the throttle bucket:
// the device's when the account knows it, else untrusted (TDD-07 §4). A native client's cookie
// is ignored.
func (s *SignIn) bucket(ctx context.Context, c SignInClient, accountID uuid.UUID, cookie string) (*uuid.UUID, account.Bucket, error) {
	if c.BodyTransport || cookie == "" {
		return nil, account.UntrustedBucket, nil
	}
	id, ok := s.d.Devices.Parse(cookie)
	if !ok {
		return nil, account.UntrustedBucket, nil
	}
	known, err := s.d.Throttles.KnownDevice(ctx, accountID, id, s.o.KnownDeviceWindow)
	if err != nil {
		return nil, "", err
	}
	if known {
		return &id, account.DeviceBucket(id), nil
	}
	return &id, account.UntrustedBucket, nil
}

// bucketKind is the bucket for the audit, without the device id.
func bucketKind(b account.Bucket) string {
	if b == account.UntrustedBucket {
		return string(b)
	}
	return "device"
}

// unknown answers an identifier that matches no account: a dummy verification, so that the time
// does not tell (TDD-03 §1.4 step 4), and INVALID_CREDENTIALS.
func (s *SignIn) unknown(ctx context.Context, e AuditEntry, op string, password flow.Secret) error {
	if _, err := s.d.Hasher.VerifyDummy(ctx, password); err != nil {
		return s.fail(ctx, e, op, err)
	}
	return s.fail(ctx, e, op, invalidCredentials())
}

// wrongPassword counts the failure in the bucket and audits it, in one transaction that locks no
// account (TDD-02 §5.1 step 5), and answers INVALID_CREDENTIALS.
func (s *SignIn) wrongPassword(ctx context.Context, e AuditEntry, op string, accountID uuid.UUID, b account.Bucket) error {
	answer := invalidCredentials()
	e.Outcome = OutcomeFailure
	e.Details = maps.Clone(e.Details)
	e.Details["code"] = string(domain.CodeInvalidCredentials)
	err := s.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		if _, err := s.d.Throttles.Fail(ctx, accountID, b, s.o.Throttle); err != nil {
			return err
		}
		return s.d.Audit.Write(ctx, e)
	})
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return answer
}

// decide applies SDD §8.1 and the client's roles to a: nil when the sign-in goes on, else the
// refusal.
func (s *SignIn) decide(ctx context.Context, a account.Account, c SignInClient) (answer, err error) {
	facts := account.SignInFacts{IdentifierVerified: true, PasswordCorrect: true, RestrictedSignIn: s.o.RestrictedSignIn}
	if err := account.SignIn(a.Status, facts).Err(); err != nil {
		return err, nil
	}
	roles, err := s.roleNames(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	if _, err := account.TokenRoles(roles, c.AllowedRoles); err != nil {
		return err, nil
	}
	return nil, nil
}

// recheck decides again under the account lock (TDD-02 §5.1 step 8). The identifier must still be
// the account's, verified and current, and the password the one verified: else
// INVALID_CREDENTIALS. A changed status or role set is decided by its new value.
func (s *SignIn) recheck(ctx context.Context, la account.Account, c SignInClient, idType, value string, cred account.PasswordCredential) (answer, err error) {
	id, err := s.d.Accounts.FindVerified(ctx, idType, value)
	if hasCode(err, domain.CodeNotFound) || (err == nil && id.AccountID != la.ID) {
		return invalidCredentials(), nil
	} else if err != nil {
		return nil, err
	}
	now, err := s.d.Accounts.PasswordCredential(ctx, la.ID)
	if hasCode(err, domain.CodeNotFound) || (err == nil && (now.Hash != cred.Hash || now.PepperKID != cred.PepperKID)) {
		return invalidCredentials(), nil
	} else if err != nil {
		return nil, err
	}
	return s.decide(ctx, la, c)
}

// secondStep returns the second step the account must take on client c (TDD-03 §3.4), empty for
// none.
func (s *SignIn) secondStep(ctx context.Context, accountID uuid.UUID, c SignInClient) (StepCode, error) {
	confirmed, err := s.confirmedTOTP(ctx, accountID)
	switch {
	case err != nil:
		return "", err
	case confirmed:
		return StepMFARequired, nil
	case c.MFARequired:
		return StepMFAEnrolmentRequired, nil
	}
	return "", nil
}

// confirmedTOTP reports whether the account has a confirmed TOTP factor.
func (s *SignIn) confirmedTOTP(ctx context.Context, accountID uuid.UUID) (bool, error) {
	f, err := s.d.Accounts.TOTPFactor(ctx, accountID)
	if hasCode(err, domain.CodeNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return f.ConfirmedAt != nil, nil
}

// openStep opens the sign_in flow of a second step under the handle, with the device of a valid
// cookie for the session that completes it.
func (s *SignIn) openStep(ctx context.Context, accountID uuid.UUID, clientID string, code StepCode, device *uuid.UUID, handle flow.Secret) (SignInStep, error) {
	step := flow.StepSecondFactor
	if code == StepMFAEnrolmentRequired {
		step = flow.StepEnrolment
	}
	h := sha256.Sum256(handle)
	st := SignInStep{Code: code, FlowID: s.d.IDs.New(), Handle: handle, ExpiresAt: s.d.Clock.Now().Add(s.o.FlowTTL)}
	err := s.d.Flows.Open(ctx, flow.NewFlow{
		ID: st.FlowID, Kind: flow.KindSignIn, AccountID: accountID, ClientID: clientID, HandleHash: h[:],
		State: flow.SignInState{FirstFactor: flow.FirstFactorPassword, Step: step, DeviceID: device}, ExpiresAt: st.ExpiresAt,
	})
	return st, err
}

// roleNames returns the names of the account's roles.
func (s *SignIn) roleNames(ctx context.Context, accountID uuid.UUID) ([]string, error) {
	roles, err := s.d.Accounts.Roles(ctx, accountID)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return names, nil
}

// fail answers a step that did not go through, as Registration.fail does: a domain error is
// audited outside any transaction with its code and returned alone; any other error is returned
// wrapped with op, unaudited.
func (s *SignIn) fail(ctx context.Context, e AuditEntry, op string, err error) error {
	var de *domain.Error
	if !errors.As(err, &de) {
		return fmt.Errorf("%s: %w", op, err)
	}
	e.Outcome = OutcomeFailure
	e.Details = maps.Clone(e.Details)
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	e.Details["code"] = string(de.Code)
	if aerr := s.d.Audit.Write(ctx, e); aerr != nil {
		s.d.Logger.LogAttrs(ctx, slog.LevelError, "audit write failed",
			slog.String("action", e.Action), slog.String("code", string(de.Code)), slog.String("error", aerr.Error()))
	}
	return err
}

// settle ends a step after its transaction: err is the transaction's failure, answer the refusal
// it decided.
func (s *SignIn) settle(ctx context.Context, e AuditEntry, op string, err, answer error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if answer != nil {
		return s.fail(ctx, e, op, answer)
	}
	return nil
}

// invalidCredentials is the answer for an unknown identifier, a wrong password and a deleted
// account alike.
func invalidCredentials() error {
	return &domain.Error{Code: domain.CodeInvalidCredentials, Detail: "the identifier or password is wrong"}
}

// ceilSecond rounds d up to a whole second, for Retry-After.
func ceilSecond(d time.Duration) time.Duration {
	if r := d % time.Second; r != 0 {
		d += time.Second - r
	}
	return d
}

// maxUserAgent is the most of a User-Agent header kept, in bytes.
const maxUserAgent = 512

// userAgent returns ua cut to maxUserAgent bytes at a character boundary, and valid UTF-8.
func userAgent(ua string) string {
	ua = strings.ToValidUTF8(ua, "")
	if len(ua) <= maxUserAgent {
		return ua
	}
	cut := maxUserAgent
	for cut > 0 && !utf8.RuneStart(ua[cut]) {
		cut--
	}
	return ua[:cut]
}
