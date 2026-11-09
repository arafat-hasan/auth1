package app

import "github.com/google/uuid"

// The lifecycle event types (api/asyncapi.yaml, TDD-06 §4).
const (
	EventIdentifierVerified  = "account.identifier_verified"
	EventRegistrationExpired = "account.registration_expired"
)

// EventActor is who caused a change, as the contract's Actor. Its kind is account, service,
// operator or system, never anonymous: build it with AccountActor (and its siblings as they come).
type EventActor struct {
	Kind       ActorKind `json:"kind"`
	ID         string    `json:"id,omitempty"`
	OnBehalfOf string    `json:"on_behalf_of,omitempty"`
}

// AccountActor is the account id acting for itself.
func AccountActor(id uuid.UUID) EventActor {
	return EventActor{Kind: ActorAccount, ID: id.String()}
}

// SystemActor is auth1 acting through one of its jobs, the job's name as its id (TDD-08 §7).
func SystemActor(job string) EventActor {
	return EventActor{Kind: ActorSystem, ID: job}
}

// IdentifierVerified is the data of account.identifier_verified: an identifier was verified at
// registration, at invitation acceptance or by a resume. It names the identifier, never its value
// (T-9).
type IdentifierVerified struct {
	AccountID      uuid.UUID  `json:"account_id"`
	IdentifierID   uuid.UUID  `json:"identifier_id"`
	IdentifierType string     `json:"identifier_type"`
	Actor          EventActor `json:"actor"`
}

// RegistrationExpired is the data of account.registration_expired: a registration or invitation
// expired before it completed, its pending account's identifiers were released and the account
// deleted (TDD-02 §2.5).
type RegistrationExpired struct {
	AccountID uuid.UUID `json:"account_id"`
	// ClientID is the client the registration started through, or "invitation".
	ClientID string     `json:"client_id"`
	Actor    EventActor `json:"actor"`
}
