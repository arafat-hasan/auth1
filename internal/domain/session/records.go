package session

import (
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// The records below are sessions and refresh tokens as the sessions repository stores them
// (TDD-01 §4, TDD-04 §2, §3): plaintext only, never ciphertext. A token is known by its SHA-256
// hash, which the caller computes. Times the repository writes, and every comparison with them,
// are the database's.

// NewSession is a session to create when a sign-in completes (TDD-04 §2). Its idle expiry is now
// + IdleTTL, capped at its absolute expiry, now + AbsoluteTTL. DeviceID is nil and UserAgent empty
// when unknown.
type NewSession struct {
	ID          uuid.UUID
	AccountID   uuid.UUID
	ClientID    string
	AMR         []string
	AuthTime    time.Time
	DeviceID    *uuid.UUID
	UserAgent   string
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
}

// Session is a row of sessions. Live is the database's judgement at the transaction's now(): not
// revoked and before both expiries.
type Session struct {
	ID                uuid.UUID
	AccountID         uuid.UUID
	ClientID          string
	AMR               []string
	AuthTime          time.Time
	DeviceID          *uuid.UUID
	UserAgent         string // empty when unknown or cleared (TDD-01 §5)
	CreatedAt         time.Time
	LastUsedAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
	RevokeReason      RevokeReason // empty while not revoked
	Live              bool
}

// Token is a row of refresh_tokens, without its successor. Hash is the SHA-256 of the token.
// InGrace is the database's judgement at the transaction's now(): the token was rotated no more
// than refresh_reuse_grace ago and its successor's value is still held (TDD-04 §3, I-13).
type Token struct {
	Hash      []byte
	SessionID uuid.UUID
	IssuedAt  time.Time
	RotatedAt *time.Time
	InGrace   bool
}

// Current reports whether the token has not been rotated.
func (t Token) Current() bool { return t.RotatedAt == nil }

// RevokeReason is why a session was revoked (TDD-04 §2), the values of sessions.revoke_reason.
type RevokeReason string

// The revoke reasons, in TDD-04 §2 order.
const (
	RevokeSignedOut       RevokeReason = "signed_out"
	RevokeUserRevoked     RevokeReason = "user_revoked"
	RevokeRefreshReuse    RevokeReason = "refresh_reuse"
	RevokePasswordChanged RevokeReason = "password_changed"
	RevokePasswordReset   RevokeReason = "password_reset"
	RevokeMFAReset        RevokeReason = "mfa_reset"
	RevokeStatusChange    RevokeReason = "status_change"
	RevokeRolesRemoved    RevokeReason = "roles_removed"
	RevokeServiceRevoked  RevokeReason = "service_revoked"
	RevokeAccountDeleted  RevokeReason = "account_deleted"
	RevokeOperator        RevokeReason = "operator"
)

var reasons = []RevokeReason{RevokeSignedOut, RevokeUserRevoked, RevokeRefreshReuse, RevokePasswordChanged,
	RevokePasswordReset, RevokeMFAReset, RevokeStatusChange, RevokeRolesRemoved, RevokeServiceRevoked,
	RevokeAccountDeleted, RevokeOperator}

// Reasons returns every revoke reason, in TDD-04 §2 order.
func Reasons() []RevokeReason { return slices.Clone(reasons) }

// ParseRevokeReason returns the reason named s, matched exactly. Any other value is
// VALIDATION_FAILED on the field "reason".
func ParseRevokeReason(s string) (RevokeReason, error) {
	if slices.Contains(reasons, RevokeReason(s)) {
		return RevokeReason(s), nil
	}
	return "", &domain.Error{
		Code:   domain.CodeValidationFailed,
		Detail: "the request has invalid fields",
		Fields: []domain.FieldError{{Field: "reason", Code: domain.FieldUnknown}},
	}
}
