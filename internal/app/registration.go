package app

import (
	"context"
	"crypto/sha256"
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
	auditRegistrationStart = "registration.start"
)

// StartRegistration is a request to start a registration (POST /v1/registrations).
type StartRegistration struct {
	ClientID    string
	DisplayName string
	Locale      string
	Identifiers map[string]string // raw value by type
	Password    []byte
	IP          netip.Addr
	UserAgent   string
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
		IP: cmd.IP, UserAgent: cmd.UserAgent}
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
