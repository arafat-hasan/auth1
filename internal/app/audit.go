package app

import (
	"context"
	"net/netip"

	"github.com/google/uuid"
)

// AuditWriter appends to the audit log, auth_audit (TDD-01 §4). Inside UnitOfWork.Do an entry
// joins the transaction and commits or rolls back with it; outside one it is written on its own,
// so a failure can be audited after its use case rolled back.
type AuditWriter interface {
	Write(ctx context.Context, e AuditEntry) error
}

// AuditEntry is one audit record. Empty strings, a zero AccountID and a zero IP are stored as
// null. Details hold no secret and no identifier value (G-6, T-9).
type AuditEntry struct {
	// AccountID is the account acted on.
	AccountID uuid.UUID
	// ActorKind is account, service, operator, system or anonymous.
	ActorKind string
	// ActorID is the account id, the service's workload identity or client id, the operator's
	// name, or the system job.
	ActorID string
	// OnBehalf is a calling service's Auth1-Actor header, verbatim.
	OnBehalf string
	// Action is what was attempted, and Outcome how it ended.
	Action, Outcome string
	// ClientID is the client the request came through.
	ClientID string
	// IP and UserAgent are the request's, cleared after 90 days (TDD-01 §5).
	IP        netip.Addr
	UserAgent string
	// Details are further non-secret facts, marshalled as a JSON object.
	Details map[string]any
}
