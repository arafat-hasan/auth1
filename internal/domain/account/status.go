package account

import (
	"slices"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// Status is an account's state (SDD D-5, §8.1).
type Status string

// The account statuses, the values of accounts.status.
const (
	StatusPending   Status = "pending"
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
	StatusBanned    Status = "banned"
	StatusDeleted   Status = "deleted"
)

// statuses is every status, in SDD order.
var statuses = []Status{StatusPending, StatusActive, StatusSuspended, StatusBanned, StatusDeleted}

// Statuses returns every status, in SDD order.
func Statuses() []Status { return slices.Clone(statuses) }

// ParseStatus returns the status named s, matched exactly. Any other value is VALIDATION_FAILED on
// the field "status".
func ParseStatus(s string) (Status, error) {
	if slices.Contains(statuses, Status(s)) {
		return Status(s), nil
	}
	return "", fieldError(domain.FieldError{Field: "status", Code: domain.FieldUnknown})
}

// Restricted reports whether an account in status s gets a restricted session: true for
// suspended and banned only (SDD D-5). These are also the statuses that carry a reason, as the
// accounts CHECK requires, so Transition uses it for both.
func Restricted(s Status) bool { return s == StatusSuspended || s == StatusBanned }

// fieldError is a VALIDATION_FAILED error listing fields.
func fieldError(fields ...domain.FieldError) error {
	return &domain.Error{Code: domain.CodeValidationFailed, Detail: "the request has invalid fields", Fields: fields}
}
