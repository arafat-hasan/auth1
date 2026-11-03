package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
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

// RegistrationOptions are the registration settings from configuration.
type RegistrationOptions struct {
	// Clients are the configured clients, by id.
	Clients map[string]RegistrationClient
	// Locales are locales.allowed.
	Locales []string
	// FlowTTL is flows.pending_registration_ttl.
	FlowTTL time.Duration
	// Password is the password policy.
	Password password.Policy
	// Resend are the per-challenge resend rules (otp.resend_after, otp.cooldown).
	Resend flow.ResendRules
}

// RegistrationDeps are the ports and components the registration steps use.
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

// NewRegistration returns the registration steps.
func NewRegistration(d RegistrationDeps, o RegistrationOptions) *Registration {
	return &Registration{d: d, o: o}
}

// The audit actions of the registration steps.
const (
	auditRegistrationStart   = "registration.start"
	auditRegistrationVerify  = "registration.verify"
	auditRegistrationResend  = "registration.resend"
	auditVerificationConfirm = "verification_link.confirm"
)

// StartRegistration is a request to start a registration (POST /v1/registrations).
type StartRegistration struct {
	ClientID    string
	DisplayName string
	Locale      string
	Identifiers map[string]string // raw value by type
	Password    []byte
	IP          netip.Addr
}

// RegistrationStarted is a started registration: the flow, its handle (returned once, stored as
// its SHA-256), the types still to verify and when the flow expires.
type RegistrationStarted struct {
	FlowID       uuid.UUID
	Handle       flow.Secret
	PendingTypes []string
	ExpiresAt    time.Time
}

// Start starts a registration (TDD-02 §3 steps 1–6). The checks run cheapest first, and the
// password is hashed only after every one of them passed (TDD-07 §2), outside the transaction.
// In the transaction: the pending account with its unverified identifiers and its password, the
// registration flow, and one verify_identifier challenge per identifier, by the type's method,
// each sent. A send the per-address limits refuse is skipped: the challenge stays open, unsent,
// for a resend (TDD-02 §3 step 5).
func (r *Registration) Start(ctx context.Context, cmd StartRegistration) (RegistrationStarted, error) {
	entry := AuditEntry{ActorKind: ActorAnonymous, Action: auditRegistrationStart, ClientID: cmd.ClientID,
		IP: cmd.IP}
	if c, ok := r.o.Clients[cmd.ClientID]; !ok || !c.SelfRegistration {
		return RegistrationStarted{}, r.fail(ctx, entry, invalidField("client_id", domain.FieldUnknown))
	}
	if err := r.d.Limits.CheckIP(ctx, RuleRegistrationIP, cmd.IP); err != nil {
		return RegistrationStarted{}, err // not audited: the per-IP limits bound the volume, not audit rows
	}
	if !slices.Contains(r.o.Locales, cmd.Locale) {
		return RegistrationStarted{}, r.fail(ctx, entry, invalidField("locale", domain.FieldUnknown))
	}
	values, err := r.d.Registry.NormaliseSet(cmd.Identifiers)
	if err != nil {
		return RegistrationStarted{}, r.fail(ctx, entry, err)
	}
	types := slices.Sorted(maps.Keys(values))
	var variants []string
	for _, t := range types {
		if _, err := r.d.Accounts.FindVerified(ctx, t, values[t]); err == nil {
			return RegistrationStarted{}, r.fail(ctx, entry,
				&domain.Error{Code: domain.CodeIdentifierTaken, Detail: "an identifier is taken"})
		} else if !hasCode(err, domain.CodeNotFound) {
			return RegistrationStarted{}, fmt.Errorf("start registration: %w", err)
		}
		variants = append(variants, r.d.Registry.Variants(t, values[t])...)
	}
	if reasons := password.Check(cmd.Password, variants, r.o.Password); len(reasons) > 0 {
		return RegistrationStarted{}, r.fail(ctx, entry, password.Rejected(reasons))
	}
	for range types {
		if err := r.d.Limits.CheckIP(ctx, RuleSendIP, cmd.IP); err != nil {
			return RegistrationStarted{}, err
		}
	}
	hash, kid, err := r.d.Hasher.Hash(ctx, cmd.Password)
	if err != nil {
		return RegistrationStarted{}, r.fail(ctx, entry, err)
	}
	handle, err := flow.NewHandle(r.d.Rand)
	if err != nil {
		return RegistrationStarted{}, fmt.Errorf("start registration: %w", err)
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
		for _, ni := range na.Identifiers {
			id := account.Identifier{ID: ni.ID, AccountID: a.ID, Type: ni.Type, Value: ni.Value}
			if err := r.openAndSend(ctx, a, flowID, id); err != nil {
				return err
			}
		}
		entry.AccountID, entry.Outcome = a.ID, OutcomeSuccess
		entry.Details = map[string]any{"flow_id": flowID.String(), "kind": string(flow.KindRegistration)}
		return r.d.Audit.Write(ctx, entry)
	})
	if err != nil {
		return RegistrationStarted{}, fmt.Errorf("start registration: %w", err)
	}
	return RegistrationStarted{FlowID: flowID, Handle: handle, PendingTypes: types, ExpiresAt: expires}, nil
}

// openAndSend opens a verify_identifier challenge on id in the flow, by the type's method, and
// sends it. A send the per-address limits refuse is skipped: the challenge stays open and unsent.
func (r *Registration) openAndSend(ctx context.Context, a account.Account, flowID uuid.UUID, id account.Identifier) error {
	t, _ := r.d.Registry.Type(id.Type)
	p, _ := r.d.Registry.Policy(id.Type)
	ch, err := r.d.Challenges.OpenVerification(ctx, flowID, id, p.Verify)
	if err != nil {
		return err
	}
	err = r.d.Challenges.Send(ctx, a, ch, id, t.Channel())
	if hasCode(err, domain.CodeResendTooSoon, domain.CodeRateLimited) {
		return nil
	}
	return err
}

// fail audits a failed step, outside any transaction, and returns err. A failure to audit joins
// err, which keeps its domain error for the answer.
func (r *Registration) fail(ctx context.Context, e AuditEntry, err error) error {
	e.Outcome = OutcomeFailure
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	var de *domain.Error
	if errors.As(err, &de) {
		e.Details["code"] = string(de.Code)
	}
	if aerr := r.d.Audit.Write(ctx, e); aerr != nil {
		return errors.Join(err, fmt.Errorf("audit: %w", aerr))
	}
	return err
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
	Handle         []byte
	IdentifierType string
	Code           []byte
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
	Handle         []byte
	IdentifierType string
	IP             netip.Addr
}

// ConfirmLink is an emailed link's token (POST /v1/verification-links/confirm).
type ConfirmLink struct {
	Token []byte
	IP    netip.Addr
}

// LinkConfirmed is a confirmed link: its purpose, its flow, whether the flow needs nothing more
// verified, and the types it still needs.
type LinkConfirmed struct {
	Purpose      flow.Purpose
	FlowID       uuid.UUID
	Complete     bool
	PendingTypes []string
}

// locked is a flow with its account, flow and challenges locked, in that order (G-5).
type locked struct {
	account    account.Account
	flow       flow.Flow
	challenges []flow.ChallengeRecord
	ids        []account.Identifier // the account's current identifiers
}

// lock locks f's account, f and its challenges, and reads the account's identifiers. It runs
// inside UnitOfWork.Do.
func (r *Registration) lock(ctx context.Context, f flow.Flow) (locked, error) {
	a, err := r.d.Accounts.GetForUpdate(ctx, f.AccountID)
	if err != nil {
		return locked{}, err
	}
	lf, err := r.d.Flows.LockFlow(ctx, f)
	if err != nil {
		return locked{}, err
	}
	chs, err := r.d.Flows.LockChallenges(ctx, lf.ID)
	if err != nil {
		return locked{}, err
	}
	ids, err := r.d.Accounts.Identifiers(ctx, a.ID)
	if err != nil {
		return locked{}, err
	}
	return locked{account: a, flow: lf, challenges: chs, ids: ids}, nil
}

// pending returns the identifier of type idType still to verify in the flow, with its newest
// verify_identifier challenge; false when the type is not pending or has no challenge.
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
// it (TDD-02 §2.2, §3). Every try counts (I-4): a wrong code is CODE_INVALID with the tries left,
// and the last wrong one closes the challenge (CHALLENGE_CLOSED). The right code consumes the
// challenge and verifies the identifier, unless another account verified the value first: then
// the challenge stays consumed and the answer is IDENTIFIER_TAKEN (I-1). Counted tries and a
// consumed challenge commit whatever the answer.
func (r *Registration) VerifyCode(ctx context.Context, cmd VerifyRegistrationCode) (RegistrationProgress, error) {
	entry := AuditEntry{ActorKind: ActorAnonymous, Action: auditRegistrationVerify, IP: cmd.IP,
		Details: map[string]any{"identifier_type": cmd.IdentifierType}}
	if err := r.d.Limits.CheckIP(ctx, RuleVerifyIP, cmd.IP); err != nil {
		return RegistrationProgress{}, err
	}
	f, err := r.findFlow(ctx, cmd.FlowID, cmd.Handle)
	if err != nil {
		return RegistrationProgress{}, r.fail(ctx, entry, err)
	}
	entry.withFlow(f)
	var (
		answer   error
		progress RegistrationProgress
	)
	err = r.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		l, err := r.lock(ctx, f)
		if err != nil {
			return err
		}
		id, ch, ok := l.pending(cmd.IdentifierType)
		if !ok || ch.Method == flow.MethodEmailLink {
			answer = challengeClosed()
			return nil
		}
		matched := subtle.ConstantTimeCompare(r.d.MAC.OTP(ch.ID, cmd.Code), ch.SecretMAC) == 1
		v := flow.Verify(ch.Challenge, matched, r.d.Clock.Now())
		if v.Outcome == flow.Closed {
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
			return nil
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
	if err != nil {
		return RegistrationProgress{}, fmt.Errorf("verify registration code: %w", err)
	}
	if answer != nil {
		return RegistrationProgress{}, r.fail(ctx, entry, answer)
	}
	return progress, nil
}

// verified consumes ch and verifies id, the challenge's identifier, then drops its type from the
// flow's pending types and emits account.identifier_verified. It returns the pending types left,
// or the answer when the challenge was consumed already (CHALLENGE_CLOSED) or the value is taken
// (IDENTIFIER_TAKEN, the challenge staying consumed).
func (r *Registration) verified(ctx context.Context, l locked, id account.Identifier, ch flow.ChallengeRecord) ([]string, error, error) {
	ok, err := r.d.Flows.CloseChallenge(ctx, ch.ID, true)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, challengeClosed(), nil
	}
	if err := r.d.Accounts.VerifyIdentifier(ctx, id.ID); hasCode(err, domain.CodeIdentifierTaken) {
		return nil, err, nil
	} else if err != nil {
		return nil, nil, err
	}
	state := withVerified(l.flow.State, id.Type)
	if err := r.d.Flows.Update(ctx, l.flow.ID, state, l.flow.Attempts); err != nil {
		return nil, nil, err
	}
	if err := r.d.Outbox.Event(ctx, EventIdentifierVerified, l.account.ID, IdentifierVerified{
		AccountID: l.account.ID, IdentifierID: id.ID, IdentifierType: id.Type,
		Actor: EventActor{Kind: string(ActorAccount), ID: l.account.ID.String()},
	}); err != nil {
		return nil, nil, err
	}
	return pendingTypes(state), nil, nil
}

// Resend sends one identifier's verification again (TDD-02 §2.4): the open challenge, at most once
// per otp.resend_after; a new challenge with a new secret once it has expired, or once the
// cooldown after its attempts ran out has passed. The per-address send limits (L-7) and the
// per-IP send window (L-8) apply. A type not pending is CHALLENGE_CLOSED.
func (r *Registration) Resend(ctx context.Context, cmd ResendRegistration) error {
	entry := AuditEntry{ActorKind: ActorAnonymous, Action: auditRegistrationResend, IP: cmd.IP,
		Details: map[string]any{"identifier_type": cmd.IdentifierType}}
	if err := r.d.Limits.CheckIP(ctx, RuleSendIP, cmd.IP); err != nil {
		return err
	}
	f, err := r.findFlow(ctx, cmd.FlowID, cmd.Handle)
	if err != nil {
		return r.fail(ctx, entry, err)
	}
	entry.withFlow(f)
	var answer error
	err = r.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		l, err := r.lock(ctx, f)
		if err != nil {
			return err
		}
		id, ch, ok := l.pending(cmd.IdentifierType)
		if !ok {
			answer = challengeClosed()
			return nil
		}
		t, _ := r.d.Registry.Type(id.Type)
		switch d := flow.DecideResend(ch.Challenge, r.d.Clock.Now(), r.o.Resend); d.Outcome {
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
	if err != nil && !errors.Is(err, errRefused) {
		return fmt.Errorf("resend registration verification: %w", err)
	}
	if answer != nil {
		return r.fail(ctx, entry, answer)
	}
	return nil
}

// errRefused rolls back a transaction whose answer is a refusal that must not commit.
var errRefused = errors.New("refused")

// ConfirmLink confirms an emailed link (TDD-02 §3). Of the link purposes, it serves
// verify_identifier; a token of another purpose, or one that matches no open challenge, is
// CHALLENGE_CLOSED. A link has no attempt counter: a wrong token matches nothing (TDD-02 §2.2).
func (r *Registration) ConfirmLink(ctx context.Context, cmd ConfirmLink) (LinkConfirmed, error) {
	entry := AuditEntry{ActorKind: ActorAnonymous, Action: auditVerificationConfirm, IP: cmd.IP}
	if err := r.d.Limits.CheckIP(ctx, RuleVerifyIP, cmd.IP); err != nil {
		return LinkConfirmed{}, err
	}
	h := sha256.Sum256(cmd.Token)
	f, found, err := r.d.Flows.FindLink(ctx, h[:])
	if err == nil && (found.Purpose != flow.PurposeVerifyIdentifier ||
		(f.Kind != flow.KindRegistration && f.Kind != flow.KindInvitation)) {
		err = challengeClosed()
	}
	if err != nil {
		return LinkConfirmed{}, r.fail(ctx, entry, err)
	}
	entry.withFlow(f)
	var (
		answer error
		out    = LinkConfirmed{Purpose: flow.PurposeVerifyIdentifier, FlowID: f.ID}
	)
	err = r.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		l, err := r.lock(ctx, f)
		if err != nil {
			return err
		}
		var ch flow.ChallengeRecord
		for _, c := range l.challenges {
			if c.ID == found.ID {
				ch = c
			}
		}
		id, ok := account.Identifier{}, false
		if ch.IdentifierID != nil {
			id, ok = l.identifier(*ch.IdentifierID)
		}
		if !ok || ch.ClosedAt != nil || ch.End(r.d.Clock.Now()) != flow.EndOpen {
			answer = challengeClosed()
			return nil
		}
		out.PendingTypes, answer, err = r.verified(ctx, l, id, ch)
		if err != nil || answer != nil {
			return err
		}
		out.Complete = len(out.PendingTypes) == 0
		return r.auditSuccess(ctx, entry, l.account.ID)
	})
	if err != nil {
		return LinkConfirmed{}, fmt.Errorf("confirm verification link: %w", err)
	}
	if answer != nil {
		return LinkConfirmed{}, r.fail(ctx, entry, answer)
	}
	return out, nil
}

// auditSuccess writes e as a success about the account, in the transaction.
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
