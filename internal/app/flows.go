package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// Flows is the repository of the flow aggregate: a flow with its challenges (TDD-01 §6, TDD-02
// §2). Records hold plaintext; the repository encrypts pending_secret, secret and target_value
// through FieldCrypto and computes target_bidx itself. Callers pass hashes and MACs: the
// repository generates no handle, code or token. Times the repository stores are the database's
// now(), the start of the transaction; expires_at is the caller's. No error text holds a hash, a
// MAC, a secret or an address.
//
// A flow is open while it is neither completed nor cancelled. Find, FindByHandle, FindLink and
// LockFlow see only open flows before expires_at, and answer every miss with the same
// CHALLENGE_CLOSED error: an unknown id, a wrong or missing handle, and an expired or closed flow
// are indistinguishable (I-20).
//
// Locks follow the order account, flow, challenge (G-5, TDD-01 §4.2). A finder reads without a
// lock and returns the flow's account; the use case then locks the account with
// Accounts.GetForUpdate, the flow with LockFlow, and its challenges with LockChallenges. A method
// that needs a lock its caller has not taken in this transaction fails without querying, and
// every method that needs a lock runs inside UnitOfWork.Do.
type Flows interface {
	// Find returns the open flow id whose handle hashes to handleHash. It locks nothing.
	Find(ctx context.Context, id uuid.UUID, handleHash []byte) (flow.Flow, error)
	// FindByHandle returns the open flow whose handle hashes to handleHash, for the steps whose
	// request carries the handle alone. It locks nothing.
	FindByHandle(ctx context.Context, handleHash []byte) (flow.Flow, error)
	// FindLink returns the open email_link challenge whose secret_mac is linkHash, the SHA-256 of
	// a link token, with its open flow. It locks nothing.
	FindLink(ctx context.Context, linkHash []byte) (flow.Flow, flow.ChallengeRecord, error)
	// LockFlow re-reads f, as a finder returned it, locking its row until the transaction ends.
	// It finds nothing unless the flow is still open, of the same account and under the same
	// handle. The account must be locked. PendingSecret is decrypted.
	LockFlow(ctx context.Context, f flow.Flow) (flow.Flow, error)
	// Open stores f and locks it. For every kind but sign_in, it first cancels the account's
	// open flow of the same kind ("replaced", or "expired" when past expires_at), closing its
	// challenges (TDD-02 §2.1). The account must be locked.
	Open(ctx context.Context, f flow.NewFlow) error
	// Update stores the open flow's state and attempts; a state of another kind is
	// flow.ErrStateInvalid. The flow must be locked.
	Update(ctx context.Context, id uuid.UUID, state flow.State, attempts int) error
	// ReplaceHandle makes handleHash the open flow's handle; the old one finds nothing after
	// (TDD-02 §4). The flow must be locked.
	ReplaceHandle(ctx context.Context, id uuid.UUID, handleHash []byte) error
	// Complete completes the open flow, erasing its pending secret, and closes its open
	// challenges, erasing their secrets, in one statement (I-5). The flow must be locked.
	Complete(ctx context.Context, id uuid.UUID) error
	// Cancel is Complete for a flow cancelled with reason.
	Cancel(ctx context.Context, id uuid.UUID, reason flow.CloseReason) error

	// LockChallenges returns every challenge of the flow, open or closed, oldest first, locking
	// their rows. It decrypts nothing. The flow must be locked.
	LockChallenges(ctx context.Context, flowID uuid.UUID) ([]flow.ChallengeRecord, error)
	// OpenChallenge stores c, open, and locks it. The flow must be locked.
	OpenChallenge(ctx context.Context, c flow.NewChallengeRecord) error
	// ChallengeSecret returns the open challenge's secret, decrypted; NOT_FOUND when it is closed.
	// The challenge must be locked.
	ChallengeSecret(ctx context.Context, id uuid.UUID) (flow.Secret, error)
	// ChallengeTarget returns the value under change that the challenge was sent to, decrypted;
	// NOT_FOUND when the challenge targets an identifier. The challenge must be locked.
	ChallengeTarget(ctx context.Context, id uuid.UUID) (string, error)
	// Attempt counts a try at the open challenge's OTP: attempts + 1 while it is below
	// max_attempts (I-4, TDD-02 §2.2). It returns the new count, or false, changing nothing, when
	// the challenge is closed or its attempts are used up. The challenge must be locked.
	Attempt(ctx context.Context, id uuid.UUID) (attempts int, ok bool, err error)
	// RecordSend counts a send of the open challenge, now, for the send limits too, and returns
	// the send number for the delivery's request id (TDD-02 §2.4); NOT_FOUND when it is closed. The
	// challenge must be locked.
	RecordSend(ctx context.Context, id uuid.UUID) (sends int, err error)
	// CloseChallenge closes the open challenge, consumed when consumed, and erases its secret in
	// the same statement (I-5). It returns false, changing nothing, when the challenge is closed
	// already, so a challenge is consumed at most once (I-4). The challenge must be locked.
	CloseChallenge(ctx context.Context, id uuid.UUID, consumed bool) (bool, error)

	// SendCounts counts the sends to the address value of type targetType over every challenge,
	// whatever account or flow opened it (I-21, TDD-07 §5). It first takes a transaction-scoped
	// lock on the address, so a check followed by RecordSend in the same transaction is exact.
	// It runs inside UnitOfWork.Do.
	SendCounts(ctx context.Context, targetType, value string, w SendWindows) (SendCounts, error)
	// ExhaustedSince returns when the latest challenge to the address closed exhausted, unconsumed
	// with its attempts used up, within the last within; nil when none did (L-9). within must be
	// positive.
	ExhaustedSince(ctx context.Context, targetType, value string, within time.Duration) (*time.Time, error)

	// Resumable returns the open registration and invitation flows, before expires_at, whose
	// account holds a current identifier of type idType with value, verified or not: at most
	// limit, newest first, each with that identifier's id (TDD-02 §4). It locks nothing.
	Resumable(ctx context.Context, idType, value string, limit int) ([]ResumeTarget, error)
	// ResumeCandidates returns the open resume challenges by code (not email_link), before
	// expires_at, to the address value of type idType, whose flows are open registration or
	// invitation flows before expires_at: at most limit, the newest challenge first (TDD-02 §4).
	// It locks nothing and decrypts nothing.
	ResumeCandidates(ctx context.Context, idType, value string, limit int) ([]ResumeCandidate, error)
}

// ResumeTarget is a flow a resume request sends to, and the identifier holding the value.
type ResumeTarget struct {
	Flow         flow.Flow
	IdentifierID uuid.UUID
}

// ResumeCandidate is an open resume challenge to a value, with its flow.
type ResumeCandidate struct {
	Flow      flow.Flow
	Challenge flow.ChallengeRecord
}

// SendWindows are the two windows of the per-address send limits (L-7): Short (60 s by default)
// and Long (1 h). Short is positive and not longer than Long.
type SendWindows struct {
	Short time.Duration
	Long  time.Duration
}

// SendCounts are the sends to one address made within each window: Short within the short window,
// Long within the long one.
type SendCounts struct {
	Short int
	Long  int
}

// ExpiringFlows are the flow queries of the expiry job (TDD-02 §2.5). Expiry closes a flow as
// "expired" with Flows.Cancel; these find what has expired and close what needs no account lock.
type ExpiringFlows interface {
	// ExpiredPending returns up to limit open registration and invitation flows past expires_at
	// whose account is pending, the earliest expiry first. It locks nothing: the job then locks
	// the account with Accounts.GetForUpdate and the flow with LockExpired.
	ExpiredPending(ctx context.Context, limit int) ([]flow.Flow, error)
	// LockExpired re-reads f, as ExpiredPending returned it, locking its row until the
	// transaction ends, so Flows.Cancel may close it. It finds nothing (NOT_FOUND) unless the flow
	// is still open, of the same account and past expires_at. The account must be locked.
	LockExpired(ctx context.Context, f flow.Flow) (flow.Flow, error)
	// CloseExpired closes, as "expired", up to limit open flows past expires_at other than the
	// registration and invitation flows of pending accounts, with their challenges, erasing every
	// secret (I-5), in one statement. It skips rows another transaction holds and takes no account
	// lock, so it does not wait for requests. It returns how many flows it closed.
	CloseExpired(ctx context.Context, limit int) (int, error)
	// CloseExpiredChallenges closes up to limit open challenges past expires_at, erasing their
	// secrets (I-5), skipping rows another transaction holds. It returns how many it closed.
	CloseExpiredChallenges(ctx context.Context, limit int) (int, error)
}
