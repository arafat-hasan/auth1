package flow

import (
	"time"

	"github.com/google/uuid"
)

// The records below are flows and challenges as the flows repository stores them (TDD-01 §4,
// TDD-02 §2): plaintext only, never ciphertext. Hashes and MACs are computed by the caller; the
// repository generates nothing. Times the repository writes are the database's; expires_at is the
// caller's.

// Flow is a row of flows. HandleHash is the SHA-256 of the handle. PendingSecret is the TOTP
// secret a totp_replacement flow holds while open; a find leaves it nil, and only a lock reads it.
type Flow struct {
	ID            uuid.UUID
	Kind          Kind
	AccountID     uuid.UUID
	ClientID      string
	HandleHash    []byte
	State         State
	PendingSecret Secret
	Attempts      int // second-factor attempts in the flow (L-10)
	ExpiresAt     time.Time
	CompletedAt   *time.Time
	CancelledAt   *time.Time
	CloseReason   CloseReason // empty while open or when completed
	CreatedAt     time.Time
}

// NewFlow is a flow to open. State must be of Kind; PendingSecret is nil except for
// totp_replacement.
type NewFlow struct {
	ID            uuid.UUID
	Kind          Kind
	AccountID     uuid.UUID
	ClientID      string
	HandleHash    []byte
	State         State
	PendingSecret Secret
	ExpiresAt     time.Time
}

// ChallengeRecord is a row of challenges without its secret or target value: Challenge holds what
// the verification and resend decisions read.
type ChallengeRecord struct {
	ID           uuid.UUID
	FlowID       uuid.UUID
	Purpose      Purpose
	Method       Method
	IdentifierID *uuid.UUID // nil when the target is a value under change
	SecretMAC    []byte     // the OTP's MAC, or the link token's SHA-256
	Sends        int
	CreatedAt    time.Time
	Challenge
}

// NewChallengeRecord is a challenge to open. TargetValue is the normalised address it is sent to,
// of type TargetType: always given, for the blind index that send limits read (I-21), and stored,
// encrypted, only when IdentifierID is nil. Secret is the OTP or link token, kept encrypted while
// the challenge is open.
type NewChallengeRecord struct {
	ID           uuid.UUID
	FlowID       uuid.UUID
	Purpose      Purpose
	Method       Method
	IdentifierID *uuid.UUID
	TargetType   string
	TargetValue  string
	SecretMAC    []byte
	Secret       Secret
	MaxAttempts  int
	ExpiresAt    time.Time
}
