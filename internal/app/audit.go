package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/uuid"
)

// AuditWriter appends to the audit log, auth_audit (TDD-01 §4). Inside UnitOfWork.Do an entry
// joins the transaction and commits or rolls back with it; outside one it is written on its own,
// so a failure can be audited after its use case rolled back. An entry that Check refuses is not
// written.
type AuditWriter interface {
	Write(ctx context.Context, e AuditEntry) error
}

// ErrAuditEntryInvalid is the error for an entry with an unknown actor kind or outcome, or no
// action: a caller's bug, refused before it reaches the log.
var ErrAuditEntryInvalid = errors.New("app: audit entry invalid")

// ActorKind is who acted (TDD-01 §4).
type ActorKind string

// The actor kinds.
const (
	ActorAccount   ActorKind = "account"
	ActorService   ActorKind = "service"
	ActorOperator  ActorKind = "operator"
	ActorSystem    ActorKind = "system"
	ActorAnonymous ActorKind = "anonymous"
)

// Valid reports whether k is one of the actor kinds.
func (k ActorKind) Valid() bool {
	switch k {
	case ActorAccount, ActorService, ActorOperator, ActorSystem, ActorAnonymous:
		return true
	}
	return false
}

// Outcome is how an audited action ended (TDD-01 §4). What a failure was goes in the details.
type Outcome string

// The outcomes.
const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
)

// Valid reports whether o is one of the outcomes.
func (o Outcome) Valid() bool {
	return o == OutcomeSuccess || o == OutcomeFailure
}

// AuditEntry is one audit record. Empty strings, a zero AccountID and a zero IP are stored as
// null. Details hold no secret and no identifier value (G-6, T-9).
type AuditEntry struct {
	// AccountID is the account acted on.
	AccountID uuid.UUID
	// ActorKind is who acted.
	ActorKind ActorKind
	// ActorID is the account id, the service's workload identity or client id, the operator's
	// name, or the system job.
	ActorID string
	// OnBehalf is a calling service's Auth1-Actor header, verbatim.
	OnBehalf string
	// Action is what was attempted.
	Action string
	// Outcome is how it ended.
	Outcome Outcome
	// ClientID is the client the request came through.
	ClientID string
	// IP and UserAgent are the request's, cleared after 90 days (TDD-01 §5).
	IP        netip.Addr
	UserAgent string
	// Details are further non-secret facts, marshalled as a JSON object.
	Details map[string]any
}

// Check returns ErrAuditEntryInvalid, naming the field, for an unknown actor kind or outcome or
// an empty action.
func (e AuditEntry) Check() error {
	switch {
	case !e.ActorKind.Valid():
		return fmt.Errorf("%w: actor kind %q", ErrAuditEntryInvalid, e.ActorKind)
	case !e.Outcome.Valid():
		return fmt.Errorf("%w: outcome %q", ErrAuditEntryInvalid, e.Outcome)
	case e.Action == "":
		return fmt.Errorf("%w: no action", ErrAuditEntryInvalid)
	}
	return nil
}
