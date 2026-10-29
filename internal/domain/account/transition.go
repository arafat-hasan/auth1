package account

import (
	"slices"
	"time"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// Change is a status change asked for through account control (SDD D-14, `StatusChange`).
type Change struct {
	To             Status
	ReasonCode     string     // required for suspended and banned, else empty
	Until          *time.Time // suspended only, and after now; information only (SDD D-5)
	AllowedReasons []string   // statuses.reason_codes
}

// Effects are what a transition does beyond the account row. Only deletion has any (SDD D-5,
// TDD-02 §9). Revoking sessions at a caller's request (`revoke_sessions`) is not among them.
type Effects struct {
	RevokeSessions     bool // revoke every session
	CancelFlows        bool // cancel the open flows and close their challenges
	EraseCredentials   bool // delete the password hash, the TOTP factor and the recovery codes
	ReleaseIdentifiers bool // retire every identifier
}

// Decision is the outcome of an accepted status change. When Changed is false the change is a
// no-op: the caller answers 200 and writes nothing. When it is true, the caller stores Status,
// Reason and Until as they are (empty and nil mean NULL) and applies Effects; the row satisfies
// the accounts CHECKs.
type Decision struct {
	Changed bool
	Status  Status
	Reason  string
	Until   *time.Time // in UTC
	Effects Effects
}

// cell is the kind of a cell of the SDD §8.1 transition table.
type cell int

const (
	refused cell = iota // the zero value, so a pair not in the table is refused
	allowed
	noop
)

type pair struct{ from, to Status }

// transitions is the SDD §8.1 table (0.10). Pairs not listed, and pending as a target, are refused.
var transitions = map[pair]cell{
	{StatusPending, StatusDeleted}: allowed,

	{StatusActive, StatusActive}:    noop,
	{StatusActive, StatusSuspended}: allowed,
	{StatusActive, StatusBanned}:    allowed,
	{StatusActive, StatusDeleted}:   allowed,

	{StatusSuspended, StatusActive}:    allowed,
	{StatusSuspended, StatusSuspended}: allowed,
	{StatusSuspended, StatusBanned}:    allowed,
	{StatusSuspended, StatusDeleted}:   allowed,

	{StatusBanned, StatusActive}:    allowed,
	{StatusBanned, StatusSuspended}: allowed,
	{StatusBanned, StatusBanned}:    allowed,
	{StatusBanned, StatusDeleted}:   allowed,

	{StatusDeleted, StatusDeleted}: noop,
}

// Transition decides the status change req for an account in status from, at now (SDD §8.1).
// The request is validated first, whatever from is: an invalid one is VALIDATION_FAILED with
// every failing field, in the order status, reason_code, until. A cell the table refuses is
// STATUS_TRANSITION_INVALID.
func Transition(from Status, req Change, now time.Time) (Decision, error) {
	if err := validate(req, now); err != nil {
		return Decision{}, err
	}
	switch transitions[pair{from, req.To}] {
	case noop:
		return Decision{Status: from}, nil
	case allowed:
		d := Decision{Changed: true, Status: req.To}
		if Restricted(req.To) {
			d.Reason = req.ReasonCode
		}
		if req.To == StatusSuspended && req.Until != nil {
			until := req.Until.UTC()
			d.Until = &until
		}
		if req.To == StatusDeleted {
			d.Effects = Effects{RevokeSessions: true, CancelFlows: true, EraseCredentials: true, ReleaseIdentifiers: true}
		}
		return d, nil
	default:
		return Decision{}, &domain.Error{
			Code:   domain.CodeStatusTransitionInvalid,
			Detail: "the account cannot change from " + string(from) + " to " + string(req.To),
		}
	}
}

// validate checks req against the contract and the accounts CHECKs: a known target other than
// pending; a listed reason exactly for suspended and banned; an until after now, for suspended only.
func validate(req Change, now time.Time) error {
	to, err := ParseStatus(string(req.To))
	if err != nil {
		return err
	}
	if to == StatusPending {
		return fieldError(domain.FieldError{Field: "status", Code: FieldNotAllowed})
	}
	var fields []domain.FieldError
	switch {
	case !Restricted(to) && req.ReasonCode != "":
		fields = append(fields, domain.FieldError{Field: "reason_code", Code: FieldNotAllowed})
	case Restricted(to) && req.ReasonCode == "":
		fields = append(fields, domain.FieldError{Field: "reason_code", Code: FieldRequired})
	case Restricted(to) && !slices.Contains(req.AllowedReasons, req.ReasonCode):
		fields = append(fields, domain.FieldError{Field: "reason_code", Code: FieldUnknown})
	}
	switch {
	case req.Until == nil:
	case to != StatusSuspended:
		fields = append(fields, domain.FieldError{Field: "until", Code: FieldNotAllowed})
	case !req.Until.After(now):
		fields = append(fields, domain.FieldError{Field: "until", Code: FieldNotFuture})
	}
	if len(fields) > 0 {
		return fieldError(fields...)
	}
	return nil
}
