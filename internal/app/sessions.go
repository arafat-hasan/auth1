package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/session"
)

// Sessions is the repository of the session aggregate: a session with its refresh tokens
// (TDD-01 §6, TDD-04 §2, §3). Records hold plaintext. Callers pass token hashes (SHA-256) and the
// successor's raw value; the repository stores the hash only and seals the successor through
// FieldCrypto, at the presented token's row. It generates no token. No error text holds a hash or
// a token.
//
// Times the repository stores, but for the caller's AuthTime, and every time it compares are the
// database's now(), the start of the transaction: one clock for every replica, so skew between replicas never widens the grace
// window (R-3). A token is within the grace window when it was rotated no more than grace ago and
// its successor's value is still held; EraseSuccessors removes the values of tokens rotated more
// than grace ago, and nothing reads one past the window whether or not the erase has run (I-13).
//
// Locks follow G-5 (TDD-01 §4.2): account, flow, challenge, session; this repository checks the
// account before its sessions, and Accounts.GetForUpdate refuses once a session is locked. The
// refresh path locks the
// session alone, through FindToken, and never the account after it. A method that needs a lock
// its caller has not taken in this transaction fails without querying, and every method that
// needs a lock runs inside UnitOfWork.Do.
type Sessions interface {
	// Create stores s with its first refresh token, whose hash is tokenHash, and locks the
	// session. The account must be locked.
	Create(ctx context.Context, s session.NewSession, tokenHash []byte) error
	// FindToken returns the token whose hash is tokenHash and its session, locking the session
	// until the transaction ends (TDD-04 §3 step 1), and reads the token after taking the lock, so a
	// refresh that waited for a racing rotation sees the token rotated. A revoked or expired session
	// is returned with Live false; an unknown token is SESSION_INVALID. grace is refresh_reuse_grace. It runs
	// inside UnitOfWork.Do.
	FindToken(ctx context.Context, tokenHash []byte, grace time.Duration) (session.Token, session.Session, error)
	// LockSession returns the session id of the account, locking it until the transaction ends;
	// NOT_FOUND when the account has none by that id. It runs inside UnitOfWork.Do.
	LockSession(ctx context.Context, accountID, id uuid.UUID) (session.Session, error)
	// Rotate marks the current token tokenHash of the session rotated, with the successor whose
	// hash is successorHash and whose raw value is successor, stores the successor as current,
	// and touches the session: last_used_at now, idle expiry now + idleTTL capped at the absolute
	// one. It returns false, changing nothing, when the token is not a current token of the
	// session, so a token rotates at most once (I-3). The session must be locked.
	Rotate(ctx context.Context, sessionID uuid.UUID, tokenHash, successorHash []byte, successor session.Secret, idleTTL time.Duration) (bool, error)
	// Successor follows the successors of the session's token tokenHash, at most 3 steps, each
	// from a token within the grace window, to a current token, and returns that token's raw
	// value (TDD-04 §3 step 4). It returns false when the chain leaves the window, the session or
	// the step limit, or when tokenHash is itself current: the presentation is reuse. A rotated
	// token in the window whose successor is not stored is an error, not reuse: Rotate never
	// writes such a chain. It stores nothing. The session must be locked.
	Successor(ctx context.Context, sessionID uuid.UUID, tokenHash []byte, grace time.Duration) (session.Secret, bool, error)
	// Revoke revokes the session for reason, one of session.Reasons() (else
	// session.ErrRevokeReason). It returns false, changing nothing, when the session was revoked
	// already. The session must be locked.
	Revoke(ctx context.Context, id uuid.UUID, reason session.RevokeReason) (bool, error)
	// RevokeAll revokes every live session of the account for reason and returns how many. The
	// account must be locked.
	RevokeAll(ctx context.Context, accountID uuid.UUID, reason session.RevokeReason) (int, error)
	// RevokeAllExcept is RevokeAll sparing the session keep.
	RevokeAllExcept(ctx context.Context, accountID, keep uuid.UUID, reason session.RevokeReason) (int, error)
	// ListLive returns the account's live sessions, newest first. It locks nothing.
	ListLive(ctx context.Context, accountID uuid.UUID) ([]session.Session, error)
	// EraseSuccessors removes the successor's value from every token rotated more than grace ago
	// and returns how many (I-13, TDD-04 §3). grace is refresh_reuse_grace.
	EraseSuccessors(ctx context.Context, grace time.Duration) (int64, error)
}
