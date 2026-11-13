package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/identifier"
	"github.com/arafat-hasan/auth1/internal/domain/password"
)

// RegistrationClient is what registration needs of a configured client (SDD D-6).
type RegistrationClient struct {
	ID               string
	SelfRegistration bool
}

// RegistrationOptions are the registration settings from configuration. The resend rules are the
// challenges' (Challenges.ResendRules).
type RegistrationOptions struct {
	// Clients are the configured clients, by id.
	Clients map[string]RegistrationClient
	// Locales are locales.allowed.
	Locales []string
	// FlowTTL is flows.pending_registration_ttl; above 0.
	FlowTTL time.Duration
	// Password is the password policy.
	Password password.Policy
	// FactorLimit is L-11, rate_limits.factor_failures: a limit and a window above 0.
	FactorLimit account.FactorLimit
}

// RegistrationDeps are the ports and components the registration steps use. Every field is
// required.
type RegistrationDeps struct {
	UnitOfWork UnitOfWork
	Accounts   Accounts
	Flows      Flows
	Challenges *Challenges
	Outbox     OutboxWriter
	Audit      AuditWriter
	Hasher     PasswordHasher
	Registry   *identifier.Registry
	Limits     *RateLimits
	IDs        IDGenerator
	Clock      Clock
	Rand       io.Reader // crypto/rand.Reader outside tests
	MAC        MAC
	Logger     *slog.Logger // for what cannot be answered or audited, such as a lost audit entry
}

// missing returns the names of the fields of d that are nil.
func (d RegistrationDeps) missing() []string {
	fields := []struct {
		name string
		nil  bool
	}{
		{"UnitOfWork", d.UnitOfWork == nil}, {"Accounts", d.Accounts == nil}, {"Flows", d.Flows == nil},
		{"Challenges", d.Challenges == nil}, {"Outbox", d.Outbox == nil}, {"Audit", d.Audit == nil},
		{"Hasher", d.Hasher == nil}, {"Registry", d.Registry == nil}, {"Limits", d.Limits == nil},
		{"IDs", d.IDs == nil}, {"Clock", d.Clock == nil}, {"Rand", d.Rand == nil}, {"MAC", d.MAC == nil},
		{"Logger", d.Logger == nil},
	}
	var out []string
	for _, f := range fields {
		if f.nil {
			out = append(out, f.name)
		}
	}
	return out
}

// Registration is the registration flow (TDD-02 §3): start, verify an identifier by code or by
// link, and resend a verification. Each step hashes nothing and calls no network inside its one
// transaction (G-4), and takes its locks in the order account, flow, challenges (G-5). Every miss
// answers the same CHALLENGE_CLOSED (I-20). No identifier value, code, token, handle or password
// goes into an error, an event or an audit entry (G-6).
type Registration struct {
	d RegistrationDeps
	o RegistrationOptions
}

// NewRegistration returns the registration steps, or an error naming the missing dependencies or
// the bad option. It keeps its own copies of the options' clients and locales.
func NewRegistration(d RegistrationDeps, o RegistrationOptions) (*Registration, error) {
	if m := d.missing(); len(m) > 0 {
		return nil, fmt.Errorf("registration: missing %s", strings.Join(m, ", "))
	}
	if o.FlowTTL <= 0 {
		return nil, errors.New("registration: the flow lifetime must be above 0")
	}
	if o.FactorLimit.Limit < 1 || o.FactorLimit.Window <= 0 {
		return nil, errors.New("registration: the factor failure limit and window must be above 0")
	}
	o.Clients, o.Locales = maps.Clone(o.Clients), slices.Clone(o.Locales)
	return &Registration{d: d, o: o}, nil
}

// The audit actions of the registration steps.
const (
	auditRegistrationStart   = "registration.start"
	auditRegistrationVerify  = "registration.verify"
	auditRegistrationResend  = "registration.resend"
	auditVerificationConfirm = "verification_link.confirm"
)

// StartRegistration is a request to start a registration (POST /v1/registrations). It formats and
// logs as its client, locale and identifier types only: never the values, the display name or the
// password.
type StartRegistration struct {
	ClientID    string
	DisplayName string
	Locale      string
	Identifiers map[string]string // raw value by type
	Password    flow.Secret
	IP          netip.Addr
}

// String describes the request without its personal or secret fields.
func (c StartRegistration) String() string {
	return fmt.Sprintf("StartRegistration{client: %s, locale: %s, types: %v}", c.ClientID, c.Locale,
		slices.Sorted(maps.Keys(c.Identifiers)))
}

// GoString is String.
func (c StartRegistration) GoString() string { return c.String() }

// Format writes String for every verb.
func (c StartRegistration) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }

// LogValue implements slog.LogValuer with String.
func (c StartRegistration) LogValue() slog.Value { return slog.StringValue(c.String()) }

// RegistrationStarted is a started registration: the flow, its handle (returned once, stored as
// its SHA-256), the types still to verify and when the flow expires.
type RegistrationStarted struct {
	FlowID       uuid.UUID
	Handle       flow.Secret
	PendingTypes []string
	ExpiresAt    time.Time
}

// Start starts a registration (TDD-02 §3 steps 1–6). The checks run cheapest first: the client,
// L-4, the locale, the identifiers, values verified elsewhere, the password policy, then L-8 once
// per identifier; the password is hashed only after every one of them passed (TDD-07 §2), outside
// the transaction. Refusals by L-4 and L-8 are not audited; the others are. In the transaction:
// the pending account with its unverified identifiers and its password, the registration flow,
// and one verify_identifier challenge per identifier, by the type's method, each sent. A send the
// per-address limits refuse is skipped: the challenge stays open, unsent, for a resend (TDD-02 §3
// step 5), and the success audit names the unsent types.
func (r *Registration) Start(ctx context.Context, cmd StartRegistration) (RegistrationStarted, error) {
	const op = "start registration"
	entry := AuditEntry{ActorKind: ActorAnonymous, Action: auditRegistrationStart, ClientID: cmd.ClientID,
		IP: cmd.IP}
	if c, ok := r.o.Clients[cmd.ClientID]; !ok || !c.SelfRegistration {
		return RegistrationStarted{}, r.fail(ctx, entry, op, invalidField("client_id", domain.FieldUnknown))
	}
	if err := r.d.Limits.CheckIP(ctx, RuleRegistrationIP, cmd.IP); err != nil {
		return RegistrationStarted{}, err // not audited: the per-IP limits bound the volume, not audit rows
	}
	if !slices.Contains(r.o.Locales, cmd.Locale) {
		return RegistrationStarted{}, r.fail(ctx, entry, op, invalidField("locale", domain.FieldUnknown))
	}
	values, err := r.d.Registry.NormaliseSet(cmd.Identifiers)
	if err != nil {
		return RegistrationStarted{}, r.fail(ctx, entry, op, err)
	}
	types := slices.Sorted(maps.Keys(values))
	var variants []string
	for _, t := range types {
		if _, err := r.d.Accounts.FindVerified(ctx, t, values[t]); err == nil {
			return RegistrationStarted{}, r.fail(ctx, entry, op,
				&domain.Error{Code: domain.CodeIdentifierTaken, Detail: "an identifier is taken"})
		} else if !hasCode(err, domain.CodeNotFound) {
			return RegistrationStarted{}, fmt.Errorf("%s: %w", op, err)
		}
		variants = append(variants, r.d.Registry.Variants(t, values[t])...)
	}
	if reasons := password.Check(cmd.Password, variants, r.o.Password); len(reasons) > 0 {
		return RegistrationStarted{}, r.fail(ctx, entry, op, password.Rejected(reasons))
	}
	for range types {
		if err := r.d.Limits.CheckIP(ctx, RuleSendIP, cmd.IP); err != nil {
			return RegistrationStarted{}, err
		}
	}
	hash, kid, err := r.d.Hasher.Hash(ctx, cmd.Password)
	if err != nil {
		return RegistrationStarted{}, r.fail(ctx, entry, op, err)
	}
	handle, err := flow.NewHandle(r.d.Rand)
	if err != nil {
		return RegistrationStarted{}, fmt.Errorf("%s: %w", op, err)
	}

	now := r.d.Clock.Now()
	expires := now.Add(r.o.FlowTTL)
	na := account.NewAccount{
		ID: r.d.IDs.New(), DisplayName: cmd.DisplayName, Locale: cmd.Locale, RegisteredVia: cmd.ClientID,
		Password: account.PasswordCredential{Hash: hash, PepperKID: kid},
	}
	for _, t := range types {
		na.Identifiers = append(na.Identifiers, account.NewIdentifier{ID: r.d.IDs.New(), Type: t, Value: values[t]})
	}
	flowID := r.d.IDs.New()
	h := sha256.Sum256(handle)
	err = r.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		if err := r.d.Accounts.Create(ctx, na); err != nil {
			return err
		}
		a, err := r.d.Accounts.GetForUpdate(ctx, na.ID)
		if err != nil {
			return err
		}
		if err := r.d.Flows.Open(ctx, flow.NewFlow{
			ID: flowID, Kind: flow.KindRegistration, AccountID: a.ID, ClientID: cmd.ClientID, HandleHash: h[:],
			State: flow.RegistrationState{PendingTypes: types}, ExpiresAt: expires,
		}); err != nil {
			return err
		}
		var unsent []string
		for _, ni := range na.Identifiers {
			id := account.Identifier{ID: ni.ID, AccountID: a.ID, Type: ni.Type, Value: ni.Value}
			sent, err := r.openAndSend(ctx, a, flowID, id)
			if err != nil {
				return err
			}
			if !sent {
				unsent = append(unsent, ni.Type)
			}
		}
		entry.AccountID, entry.Outcome = a.ID, OutcomeSuccess
		entry.Details = map[string]any{"flow_id": flowID.String(), "kind": string(flow.KindRegistration)}
		if len(unsent) > 0 {
			entry.Details["unsent_types"] = unsent
		}
		return r.d.Audit.Write(ctx, entry)
	})
	if err != nil {
		return RegistrationStarted{}, fmt.Errorf("%s: %w", op, err)
	}
	return RegistrationStarted{FlowID: flowID, Handle: handle, PendingTypes: types, ExpiresAt: expires}, nil
}

// openAndSend opens a verify_identifier challenge on id in the flow, by the type's method, and
// sends it. A send the per-address limits refuse is skipped: the challenge stays open and unsent,
// and sent is false.
func (r *Registration) openAndSend(ctx context.Context, a account.Account, flowID uuid.UUID, id account.Identifier) (sent bool, err error) {
	t, tok := r.d.Registry.Type(id.Type)
	p, pok := r.d.Registry.Policy(id.Type)
	if !tok || !pok {
		return false, fmt.Errorf("identifier type %q is not configured", id.Type)
	}
	ch, err := r.d.Challenges.OpenVerification(ctx, flowID, id, p.Verify)
	if err != nil {
		return false, err
	}
	err = r.d.Challenges.Send(ctx, a, ch, id, t.Channel())
	if hasCode(err, domain.CodeResendTooSoon, domain.CodeRateLimited) {
		return false, nil
	}
	return err == nil, err
}

// fail answers a step that did not go through. A domain error is a refusal: it is audited,
// outside any transaction, with its code (and the flow's id and kind once the flow was found),
// and returned alone; an audit entry that cannot be written is logged. Any other error is a
// failure of the stores: it is returned wrapped with op, unaudited.
func (r *Registration) fail(ctx context.Context, e AuditEntry, op string, err error) error {
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
	if aerr := r.d.Audit.Write(ctx, e); aerr != nil {
		r.d.Logger.LogAttrs(ctx, slog.LevelError, "audit write failed",
			slog.String("action", e.Action), slog.String("code", string(de.Code)), slog.String("error", aerr.Error()))
	}
	return err
}

// settle ends a step after its transaction: err is the transaction's failure, answer the refusal
// it committed or rolled back with.
func (r *Registration) settle(ctx context.Context, e AuditEntry, op string, err, answer error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if answer != nil {
		return r.fail(ctx, e, op, answer)
	}
	return nil
}

// invalidField is VALIDATION_FAILED on one field.
func invalidField(field, code string) error {
	return &domain.Error{Code: domain.CodeValidationFailed, Detail: "the request has invalid fields",
		Fields: []domain.FieldError{{Field: field, Code: code}}}
}

// hasCode reports whether err is a *domain.Error with one of codes.
func hasCode(err error, codes ...domain.Code) bool {
	var de *domain.Error
	return errors.As(err, &de) && slices.Contains(codes, de.Code)
}

// VerifyRegistrationCode is a code for one identifier of a registration or invitation flow
// (POST /v1/registrations/{flowId}/verify).
type VerifyRegistrationCode struct {
	FlowID         uuid.UUID
	Handle         flow.Secret
	IdentifierType string
	Code           flow.Secret
	IP             netip.Addr
}

// RegistrationProgress is what a flow still needs verified.
type RegistrationProgress struct {
	PendingTypes []string
}

// ResendRegistration asks for one identifier's verification again
// (POST /v1/registrations/{flowId}/resend).
type ResendRegistration struct {
	FlowID         uuid.UUID
	Handle         flow.Secret
	IdentifierType string
	IP             netip.Addr
}

// ConfirmLink is an emailed link's token (POST /v1/verification-links/confirm).
type ConfirmLink struct {
	Token flow.Secret
	IP    netip.Addr
}

// LinkConfirmed is a confirmed link: its purpose, its flow, whether the flow needs nothing more
// verified, and the types it still needs. A resume link also gives the flow's new handle.
type LinkConfirmed struct {
	Purpose      flow.Purpose
	FlowID       uuid.UUID
	Complete     bool
	PendingTypes []string
	Handle       flow.Secret // resume only
}

// locked is a flow with its account, flow and challenges locked, in that order (G-5).
type locked struct {
	account    account.Account
	flow       flow.Flow
	challenges []flow.ChallengeRecord // oldest first, as Flows.LockChallenges returns them
	ids        []account.Identifier   // the account's current identifiers
}

// lock locks f's account, f and its challenges, and reads the account's identifiers. It runs
// inside UnitOfWork.Do. A flow or account gone since it was found is the answer CHALLENGE_CLOSED,
// the same miss as any other (I-20); err is a failure of the stores.
func (r *Registration) lock(ctx context.Context, f flow.Flow) (l locked, answer, err error) {
	a, err := r.d.Accounts.GetForUpdate(ctx, f.AccountID)
	if hasCode(err, domain.CodeNotFound) {
		return locked{}, challengeClosed(), nil
	} else if err != nil {
		return locked{}, nil, err
	}
	lf, err := r.d.Flows.LockFlow(ctx, f)
	if hasCode(err, domain.CodeChallengeClosed) {
		return locked{}, challengeClosed(), nil
	} else if err != nil {
		return locked{}, nil, err
	}
	chs, err := r.d.Flows.LockChallenges(ctx, lf.ID)
	if err != nil {
		return locked{}, nil, err
	}
	ids, err := r.d.Accounts.Identifiers(ctx, a.ID)
	if err != nil {
		return locked{}, nil, err
	}
	return locked{account: a, flow: lf, challenges: chs, ids: ids}, nil, nil
}

// pending returns the identifier of type idType still to verify in the flow, with its newest
// verify_identifier challenge (the last, the challenges being oldest first); false when the type
// is not pending or has no challenge.
func (l locked) pending(idType string) (account.Identifier, flow.ChallengeRecord, bool) {
	if !slices.Contains(pendingTypes(l.flow.State), idType) {
		return account.Identifier{}, flow.ChallengeRecord{}, false
	}
	for _, id := range l.ids {
		if id.Type != idType || id.VerifiedAt != nil {
			continue
		}
		for i := len(l.challenges) - 1; i >= 0; i-- {
			c := l.challenges[i]
			if c.Purpose == flow.PurposeVerifyIdentifier && c.IdentifierID != nil && *c.IdentifierID == id.ID {
				return id, c, true
			}
		}
	}
	return account.Identifier{}, flow.ChallengeRecord{}, false
}

// challenge returns the locked challenge id.
func (l locked) challenge(id uuid.UUID) (flow.ChallengeRecord, bool) {
	for _, c := range l.challenges {
		if c.ID == id {
			return c, true
		}
	}
	return flow.ChallengeRecord{}, false
}

// identifier returns the account's current identifier id.
func (l locked) identifier(id uuid.UUID) (account.Identifier, bool) {
	for _, i := range l.ids {
		if i.ID == id {
			return i, true
		}
	}
	return account.Identifier{}, false
}

// findFlow finds the open registration or invitation flow id under handle. Any other kind is the
// same miss as no flow (I-20).
func (r *Registration) findFlow(ctx context.Context, id uuid.UUID, handle []byte) (flow.Flow, error) {
	h := sha256.Sum256(handle)
	f, err := r.d.Flows.Find(ctx, id, h[:])
	if err != nil {
		return flow.Flow{}, err
	}
	if f.Kind != flow.KindRegistration && f.Kind != flow.KindInvitation {
		return flow.Flow{}, challengeClosed()
	}
	return f, nil
}

// VerifyCode verifies one identifier of a registration or invitation flow with the code sent to
// it (TDD-02 §2.2, §3). L-12 counts the attempt first. Every try counts (I-4): a wrong code is
// CODE_INVALID with the tries left, and the last wrong one closes the challenge
// (CHALLENGE_CLOSED). The right code consumes the challenge and verifies the identifier, unless
// another account verified the value first: then the challenge stays consumed and the answer is
// IDENTIFIER_TAKEN (I-1). Counted tries and a consumed challenge commit whatever the answer. A
// type verified by email_link, or an expired code, is CHALLENGE_CLOSED.
func (r *Registration) VerifyCode(ctx context.Context, cmd VerifyRegistrationCode) (RegistrationProgress, error) {
	const op = "verify registration code"
	entry := AuditEntry{ActorKind: ActorAnonymous, Action: auditRegistrationVerify, IP: cmd.IP,
		Details: map[string]any{"identifier_type": cmd.IdentifierType}}
	if err := r.d.Limits.CheckIP(ctx, RuleVerifyIP, cmd.IP); err != nil {
		return RegistrationProgress{}, err
	}
	f, err := r.findFlow(ctx, cmd.FlowID, cmd.Handle)
	if err != nil {
		return RegistrationProgress{}, r.fail(ctx, entry, op, err)
	}
	entry.withFlow(f)
	var (
		answer   error
		progress RegistrationProgress
	)
	err = r.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		l, miss, err := r.lock(ctx, f)
		if err != nil || miss != nil {
			answer = miss
			return err
		}
		id, ch, ok := l.pending(cmd.IdentifierType)
		if !ok || ch.Method == flow.MethodEmailLink {
			answer = challengeClosed()
			return nil
		}
		matched := subtle.ConstantTimeCompare(r.d.MAC.OTP(ch.ID, cmd.Code), ch.SecretMAC) == 1
		v := flow.Verify(ch.Challenge, matched, r.d.Clock.Now())
		if v.Outcome == flow.Closed { // closed, used up or expired: Attempt does not look at expires_at
			answer = v.Err()
			return nil
		}
		attempts, ok, err := r.d.Flows.Attempt(ctx, ch.ID)
		if err != nil {
			return err
		}
		if !ok {
			answer = challengeClosed()
			return nil
		}
		switch v.Outcome {
		case flow.Wrong:
			left := ch.MaxAttempts - attempts
			answer = &domain.Error{Code: domain.CodeCodeInvalid, Detail: "the code is wrong", AttemptsLeft: &left}
			return nil // commit: the try counts
		case flow.Exhausted:
			if _, err := r.d.Flows.CloseChallenge(ctx, ch.ID, false); err != nil {
				return err
			}
			answer = challengeClosed()
			return nil
		}
		progress.PendingTypes, answer, err = r.verified(ctx, l, id, ch)
		if err != nil || answer != nil {
			return err
		}
		return r.auditSuccess(ctx, entry, l.account.ID)
	})
	if err := r.settle(ctx, entry, op, err, answer); err != nil {
		return RegistrationProgress{}, err
	}
	return progress, nil
}

// verified consumes ch and verifies id, the challenge's identifier, then drops its type from the
// flow's pending types and emits account.identifier_verified. It returns the pending types left.
// Otherwise answer is CHALLENGE_CLOSED when the challenge has closed already or the identifier is
// no longer current, or IDENTIFIER_TAKEN when another account holds the value verified; both
// commit, the challenge staying consumed for the latter. err is a failure of the stores, which
// rolls the step back.
func (r *Registration) verified(ctx context.Context, l locked, id account.Identifier, ch flow.ChallengeRecord) (pending []string, answer, err error) {
	ok, err := r.d.Flows.CloseChallenge(ctx, ch.ID, true)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, challengeClosed(), nil
	}
	switch err := r.d.Accounts.VerifyIdentifier(ctx, id.ID); {
	case hasCode(err, domain.CodeIdentifierTaken):
		return nil, err, nil
	case hasCode(err, domain.CodeNotFound):
		return nil, challengeClosed(), nil
	case err != nil:
		return nil, nil, err
	}
	state := withVerified(l.flow.State, id.Type)
	if err := r.d.Flows.Update(ctx, l.flow.ID, state, l.flow.Attempts); err != nil {
		return nil, nil, err
	}
	if err := r.d.Outbox.Event(ctx, EventIdentifierVerified, l.account.ID, IdentifierVerified{
		AccountID: l.account.ID, IdentifierID: id.ID, IdentifierType: id.Type, Actor: AccountActor(l.account.ID),
	}); err != nil {
		return nil, nil, err
	}
	return pendingTypes(state), nil, nil
}

// Resend sends one identifier's verification again (TDD-02 §2.4): the open challenge, at most once
// per otp.resend_after; a new challenge with a new secret once it has expired, or once the
// cooldown after its attempts ran out has passed. L-8 counts the request first, and the
// per-address limits (L-7, L-9) apply to the send. Too soon, or during the cooldown, is
// RESEND_TOO_SOON; a type not pending, or a challenge consumed or closed with its flow, is
// CHALLENGE_CLOSED. A send the limits refuse rolls the step back, a replaced challenge included.
func (r *Registration) Resend(ctx context.Context, cmd ResendRegistration) error {
	const op = "resend registration verification"
	entry := AuditEntry{ActorKind: ActorAnonymous, Action: auditRegistrationResend, IP: cmd.IP,
		Details: map[string]any{"identifier_type": cmd.IdentifierType}}
	if err := r.d.Limits.CheckIP(ctx, RuleSendIP, cmd.IP); err != nil {
		return err
	}
	f, err := r.findFlow(ctx, cmd.FlowID, cmd.Handle)
	if err != nil {
		return r.fail(ctx, entry, op, err)
	}
	entry.withFlow(f)
	var answer error
	err = r.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		l, miss, err := r.lock(ctx, f)
		if err != nil || miss != nil {
			answer = miss
			return err
		}
		id, ch, ok := l.pending(cmd.IdentifierType)
		t, configured := r.d.Registry.Type(cmd.IdentifierType)
		if !ok || !configured { // a type the policy dropped since cannot be sent to
			answer = challengeClosed()
			return nil
		}
		switch d := flow.DecideResend(ch.Challenge, r.d.Clock.Now(), r.d.Challenges.ResendRules()); d.Outcome {
		case flow.Reuse:
		case flow.NewChallenge:
			if ch.ClosedAt == nil {
				if _, err := r.d.Flows.CloseChallenge(ctx, ch.ID, false); err != nil {
					return err
				}
			}
			if ch, err = r.d.Challenges.OpenVerification(ctx, l.flow.ID, id, ch.Method); err != nil {
				return err
			}
		default:
			answer = d.Err()
			return nil
		}
		if err := r.d.Challenges.Send(ctx, l.account, ch, id, t.Channel()); err != nil {
			if hasCode(err, domain.CodeResendTooSoon, domain.CodeRateLimited) {
				answer = err
				return errRefused // roll back: a refused send changes nothing
			}
			return err
		}
		return r.auditSuccess(ctx, entry, l.account.ID)
	})
	if err == errRefused { //nolint:errorlint // exactly the sentinel: a rollback failure joined to it is a failure
		err = nil
	}
	return r.settle(ctx, entry, op, err, answer)
}

// errRefused rolls back a transaction whose answer is a refusal that must not commit.
var errRefused = errors.New("refused")

// ConfirmLink confirms an emailed link (TDD-02 §3, §4). L-12 counts the attempt first. Of the link
// purposes, it serves verify_identifier and resume; a token of another purpose or flow kind, or one
// that matches no open challenge, is CHALLENGE_CLOSED. A link has no attempt counter: a wrong
// token matches nothing (TDD-02 §2.2). Complete says whether the flow has nothing left to verify.
// A resume link resumes the flow as a resume code does (VerifyResume), giving its new handle.
func (r *Registration) ConfirmLink(ctx context.Context, cmd ConfirmLink) (LinkConfirmed, error) {
	const op = "confirm verification link"
	entry := AuditEntry{ActorKind: ActorAnonymous, Action: auditVerificationConfirm, IP: cmd.IP}
	if err := r.d.Limits.CheckIP(ctx, RuleVerifyIP, cmd.IP); err != nil {
		return LinkConfirmed{}, err
	}
	h := sha256.Sum256(cmd.Token)
	f, found, err := r.d.Flows.FindLink(ctx, h[:])
	if err == nil && ((found.Purpose != flow.PurposeVerifyIdentifier && found.Purpose != flow.PurposeResume) ||
		(f.Kind != flow.KindRegistration && f.Kind != flow.KindInvitation)) {
		err = challengeClosed()
	}
	if err != nil {
		return LinkConfirmed{}, r.fail(ctx, entry, op, err)
	}
	entry.withFlow(f)
	var (
		answer error
		out    = LinkConfirmed{Purpose: found.Purpose, FlowID: f.ID}
	)
	err = r.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		l, miss, err := r.lock(ctx, f)
		if err != nil || miss != nil {
			answer = miss
			return err
		}
		// FindLink saw the challenge open; it may have closed or expired before the lock.
		ch, ok := l.challenge(found.ID)
		var id account.Identifier
		if ok && ch.IdentifierID != nil {
			id, ok = l.identifier(*ch.IdentifierID)
		}
		if !ok || ch.ClosedAt != nil || ch.End(r.d.Clock.Now()) != flow.EndOpen {
			answer = challengeClosed()
			return nil
		}
		if ch.Purpose == flow.PurposeResume {
			var res FlowResumed
			res, answer, err = r.resumeFlow(ctx, l, id, ch)
			out.PendingTypes, out.Handle = res.PendingTypes, res.Handle
		} else {
			out.PendingTypes, answer, err = r.verified(ctx, l, id, ch)
		}
		if err != nil || answer != nil {
			return err
		}
		out.Complete = len(out.PendingTypes) == 0
		return r.auditSuccess(ctx, entry, l.account.ID)
	})
	if err := r.settle(ctx, entry, op, err, answer); err != nil {
		return LinkConfirmed{}, err
	}
	return out, nil
}

// auditSuccess writes e as a success about the account, in the transaction: the holder of the
// handle or link acts for the account.
func (r *Registration) auditSuccess(ctx context.Context, e AuditEntry, accountID uuid.UUID) error {
	e.AccountID, e.Outcome = accountID, OutcomeSuccess
	e.ActorKind, e.ActorID = ActorAccount, accountID.String()
	return r.d.Audit.Write(ctx, e)
}

// withFlow adds the flow's id and kind to the entry's details, and its client.
func (e *AuditEntry) withFlow(f flow.Flow) {
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	e.Details["flow_id"], e.Details["kind"] = f.ID.String(), string(f.Kind)
	e.ClientID = f.ClientID
}

// pendingTypes returns the types a registration or invitation state still needs verified, never
// nil.
func pendingTypes(s flow.State) []string {
	var p []string
	switch st := s.(type) {
	case flow.RegistrationState:
		p = st.PendingTypes
	case flow.InvitationState:
		p = st.PendingTypes
	}
	if p == nil {
		return []string{}
	}
	return p
}

// withVerified returns the registration or invitation state s with idType verified.
func withVerified(s flow.State, idType string) flow.State {
	switch st := s.(type) {
	case flow.RegistrationState:
		return st.Verified(idType)
	case flow.InvitationState:
		st.PendingTypes = flow.RegistrationState{PendingTypes: st.PendingTypes}.Verified(idType).PendingTypes
		return st
	}
	return s
}

// challengeClosed is the answer to every miss (I-20), with the text flow.Verify gives.
func challengeClosed() error {
	return &domain.Error{Code: domain.CodeChallengeClosed, Detail: "the challenge is closed"}
}
