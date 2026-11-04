package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/session"
)

// ErrSuccessorChain is returned by Successor when a rotated token within the grace window names a
// successor that is not stored in its session. Rotate never writes such a chain, so it is damage,
// not reuse.
var ErrSuccessorChain = errors.New("postgres: refresh token successor chain broken")

// tableRefreshTokens is the table of the session aggregate's encrypted column (TDD-01 §3.1).
const tableRefreshTokens = "refresh_tokens"

// Sessions implements app.Sessions on sessions and refresh_tokens (TDD-01 §4, TDD-04 §2, §3).
type Sessions struct {
	db *bun.DB
	fc app.FieldCrypto
}

// NewSessions returns the repository on db, sealing successors through fc.
func NewSessions(db *bun.DB, fc app.FieldCrypto) *Sessions {
	return &Sessions{db: db, fc: fc}
}

// sessionInvalid is FindToken's miss (TDD-04 §3 step 1).
func sessionInvalid() error {
	return &domain.Error{Code: domain.CodeSessionInvalid, Detail: "the session is invalid"}
}

// micros is d as a whole number of microseconds, for "? * interval '1 microsecond'".
func micros(d time.Duration) int64 { return d.Microseconds() }

// sessionColumns are the columns scanSession reads, in its order. The last is the database's
// judgement that the session is live.
const sessionColumns = `s.id, s.account_id, s.client_id, s.amr, s.auth_time, s.device_id, coalesce(s.user_agent, ''),
	s.created_at, s.last_used_at, s.idle_expires_at, s.absolute_expires_at, s.revoked_at, coalesce(s.revoke_reason, ''),
	` + sessionLive

// sessionLive is the condition of a live session: not revoked and before both expiries.
const sessionLive = "(s.revoked_at IS NULL AND now() < s.idle_expires_at AND now() < s.absolute_expires_at)"

// tokenInGrace is the condition of a token r within the grace window, whose length in
// microseconds is its one argument: rotated no more than the window ago, with its successor's
// value still held (TDD-04 §3). The erase removes values just past it (EraseSuccessors), and
// nothing reads one outside it, so the erase's timing never widens the window (I-13).
//
//nolint:gosec // SQL, not a credential
const tokenInGrace = `(r.rotated_at IS NOT NULL AND r.successor_enc IS NOT NULL
	AND now() - r.rotated_at <= ? * interval '1 microsecond')`

// scanSession reads a row of sessionColumns, followed by extra.
func scanSession(row interface{ Scan(...any) error }, extra ...any) (session.Session, error) {
	var (
		s       session.Session
		device  uuid.NullUUID
		revoked sql.NullTime
		reason  string
	)
	err := row.Scan(append([]any{&s.ID, &s.AccountID, &s.ClientID, pgdialect.Array(&s.AMR), &s.AuthTime, &device,
		&s.UserAgent, &s.CreatedAt, &s.LastUsedAt, &s.IdleExpiresAt, &s.AbsoluteExpiresAt, &revoked, &reason,
		&s.Live}, extra...)...)
	if err != nil {
		return session.Session{}, err
	}
	if reason != "" {
		if s.RevokeReason, err = session.ParseRevokeReason(reason); err != nil {
			return session.Session{}, fmt.Errorf("revoke reason: %w", err)
		}
	}
	if device.Valid {
		s.DeviceID = &device.UUID
	}
	s.RevokedAt = timePtr(revoked)
	s.AuthTime, s.CreatedAt, s.LastUsedAt = s.AuthTime.UTC(), s.CreatedAt.UTC(), s.LastUsedAt.UTC()
	s.IdleExpiresAt, s.AbsoluteExpiresAt = s.IdleExpiresAt.UTC(), s.AbsoluteExpiresAt.UTC()
	return s, nil
}

// Create implements app.Sessions.
func (r *Sessions) Create(ctx context.Context, s session.NewSession, tokenHash []byte) error {
	t := txFrom(ctx)
	if t == nil {
		return fmt.Errorf("create session: %w", ErrNoTransaction)
	}
	if t.account(s.AccountID) == nil {
		return fmt.Errorf("create session: %w", ErrLockOrder)
	}
	amr := s.AMR
	if amr == nil {
		amr = []string{}
	}
	if _, err := t.tx.ExecContext(ctx, `
		WITH s AS (
			INSERT INTO sessions (id, account_id, client_id, amr, auth_time, device_id, user_agent, created_at,
				last_used_at, idle_expires_at, absolute_expires_at)
			VALUES (?, ?, ?, ?, ?, ?, nullif(?, ''), now(), now(),
				least(now() + ? * interval '1 microsecond', now() + ? * interval '1 microsecond'),
				now() + ? * interval '1 microsecond')
			RETURNING id
		)
		INSERT INTO refresh_tokens (token_hash, session_id, issued_at) SELECT ?, id, now() FROM s`,
		s.ID, s.AccountID, s.ClientID, pgdialect.Array(amr), s.AuthTime, s.DeviceID, s.UserAgent,
		micros(s.IdleTTL), micros(s.AbsoluteTTL), micros(s.AbsoluteTTL), tokenHash); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	t.lockSession(s.ID)
	return nil
}

// FindToken implements app.Sessions. It locks the session first and reads the token in a second
// statement. One statement locking the session through a join would not do: under READ COMMITTED,
// a statement that waited for the lock re-reads the locked row but keeps the token row as it was
// when the statement started, so a refresh racing a rotation would see the token still current.
func (r *Sessions) FindToken(ctx context.Context, tokenHash []byte, grace time.Duration) (session.Token, session.Session, error) {
	t := txFrom(ctx)
	if t == nil {
		return session.Token{}, session.Session{}, fmt.Errorf("find refresh token: %w", ErrNoTransaction)
	}
	s, err := scanSession(t.tx.QueryRowContext(ctx, "SELECT "+sessionColumns+` FROM sessions s
		WHERE s.id = (SELECT session_id FROM refresh_tokens WHERE token_hash = ?)
		FOR UPDATE`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return session.Token{}, session.Session{}, sessionInvalid()
	}
	if err != nil {
		return session.Token{}, session.Session{}, fmt.Errorf("find refresh token: lock session: %w", err)
	}
	t.lockSession(s.ID)
	var (
		tok     = session.Token{SessionID: s.ID}
		rotated sql.NullTime
	)
	err = t.tx.QueryRowContext(ctx, `SELECT r.token_hash, r.issued_at, r.rotated_at, `+tokenInGrace+`
		FROM refresh_tokens r WHERE r.token_hash = ? AND r.session_id = ?`, micros(grace), tokenHash, s.ID).
		Scan(&tok.Hash, &tok.IssuedAt, &rotated, &tok.InGrace)
	if errors.Is(err, sql.ErrNoRows) {
		return session.Token{}, session.Session{}, sessionInvalid()
	}
	if err != nil {
		return session.Token{}, session.Session{}, fmt.Errorf("find refresh token: %w", err)
	}
	tok.IssuedAt, tok.RotatedAt = tok.IssuedAt.UTC(), timePtr(rotated)
	return tok, s, nil
}

// LockSession implements app.Sessions.
func (r *Sessions) LockSession(ctx context.Context, accountID, id uuid.UUID) (session.Session, error) {
	t := txFrom(ctx)
	if t == nil {
		return session.Session{}, fmt.Errorf("lock session: %w", ErrNoTransaction)
	}
	s, err := scanSession(t.tx.QueryRowContext(ctx,
		"SELECT "+sessionColumns+" FROM sessions s WHERE s.id = ? AND s.account_id = ? FOR UPDATE", id, accountID))
	if errors.Is(err, sql.ErrNoRows) {
		return session.Session{}, notFound("session")
	}
	if err != nil {
		return session.Session{}, fmt.Errorf("lock session: %w", err)
	}
	t.lockSession(s.ID)
	return s, nil
}

// lockedSession returns the transaction, or the error of op when ctx carries none or the session
// id is not locked in it.
func lockedSession(ctx context.Context, op string, id uuid.UUID) (*txn, error) {
	t := txFrom(ctx)
	if t == nil {
		return nil, fmt.Errorf("%s: %w", op, ErrNoTransaction)
	}
	if !slices.Contains(t.sessions, id) {
		return nil, fmt.Errorf("%s: %w", op, ErrLockOrder)
	}
	return t, nil
}

// Rotate implements app.Sessions. One statement marks the token rotated only while it is current
// (I-3), stores the successor from that update's result, so nothing is stored when it rotates
// nothing, and touches the session.
func (r *Sessions) Rotate(ctx context.Context, sessionID uuid.UUID, tokenHash, successorHash []byte, successor session.Secret, idleTTL time.Duration) (bool, error) {
	t, err := lockedSession(ctx, "rotate refresh token", sessionID)
	if err != nil {
		return false, err
	}
	enc, err := r.fc.Seal(app.NewKeyPlace(tableRefreshTokens, "successor_enc", tokenHash), []byte(successor))
	if err != nil {
		return false, fmt.Errorf("rotate refresh token: seal successor: %w", err)
	}
	res, err := t.tx.ExecContext(ctx, `
		WITH rotated AS (
			UPDATE refresh_tokens SET rotated_at = now(), successor_hash = ?, successor_enc = ?
			WHERE token_hash = ? AND session_id = ? AND rotated_at IS NULL
			RETURNING session_id
		), stored AS (
			INSERT INTO refresh_tokens (token_hash, session_id, issued_at)
			SELECT ?, session_id, now() FROM rotated
			RETURNING session_id
		)
		UPDATE sessions SET last_used_at = now(),
			idle_expires_at = least(now() + ? * interval '1 microsecond', absolute_expires_at)
		WHERE id IN (SELECT session_id FROM stored)`,
		successorHash, enc, tokenHash, sessionID, successorHash, micros(idleTTL))
	if err != nil {
		return false, fmt.Errorf("rotate refresh token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rotate refresh token: %w", err)
	}
	return n == 1, nil
}

// maxSuccessorSteps is how many successors Successor follows at most (TDD-04 §3 step 4.1).
const maxSuccessorSteps = 3

// Successor implements app.Sessions. It reads one token per step and opens the value of the
// current token it ends at from its predecessor's successor_enc.
func (r *Sessions) Successor(ctx context.Context, sessionID uuid.UUID, tokenHash []byte, grace time.Duration) (session.Secret, bool, error) {
	t, err := lockedSession(ctx, "follow refresh token", sessionID)
	if err != nil {
		return nil, false, err
	}
	var prevHash, prevEnc []byte
	hash := tokenHash
	for step := 0; ; step++ {
		var (
			next, enc        []byte
			current, inGrace bool
		)
		err := t.tx.QueryRowContext(ctx, `
			SELECT r.successor_hash, r.successor_enc, r.rotated_at IS NULL, `+tokenInGrace+`
			FROM refresh_tokens r WHERE r.token_hash = ? AND r.session_id = ?`,
			micros(grace), hash, sessionID).Scan(&next, &enc, &current, &inGrace)
		switch {
		case errors.Is(err, sql.ErrNoRows) && step == 0:
			return nil, false, nil // not a token of the session
		case errors.Is(err, sql.ErrNoRows):
			return nil, false, fmt.Errorf("follow refresh token: step %d: %w", step, ErrSuccessorChain)
		case err != nil:
			return nil, false, fmt.Errorf("follow refresh token: %w", err)
		}
		switch {
		case current && step == 0:
			return nil, false, nil
		case current:
			value, err := r.fc.Open(app.NewKeyPlace(tableRefreshTokens, "successor_enc", prevHash), prevEnc)
			if err != nil {
				return nil, false, fmt.Errorf("follow refresh token: open successor: %w", err)
			}
			return session.Secret(value), true, nil
		case !inGrace || step == maxSuccessorSteps:
			return nil, false, nil
		case next == nil:
			return nil, false, fmt.Errorf("follow refresh token: step %d: no successor: %w", step, ErrSuccessorChain)
		}
		prevHash, prevEnc, hash = hash, enc, next
	}
}

// Revoke implements app.Sessions.
func (r *Sessions) Revoke(ctx context.Context, id uuid.UUID, reason session.RevokeReason) (bool, error) {
	t, err := lockedSession(ctx, "revoke session", id)
	if err != nil {
		return false, err
	}
	res, err := t.tx.ExecContext(ctx,
		"UPDATE sessions SET revoked_at = now(), revoke_reason = ? WHERE id = ? AND revoked_at IS NULL", reason, id)
	if err != nil {
		return false, fmt.Errorf("revoke session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("revoke session: %w", err)
	}
	return n == 1, nil
}

// RevokeAll implements app.Sessions.
func (r *Sessions) RevokeAll(ctx context.Context, accountID uuid.UUID, reason session.RevokeReason) (int, error) {
	return r.revokeAccount(ctx, "revoke sessions", accountID, uuid.Nil, reason)
}

// RevokeAllExcept implements app.Sessions.
func (r *Sessions) RevokeAllExcept(ctx context.Context, accountID, keep uuid.UUID, reason session.RevokeReason) (int, error) {
	return r.revokeAccount(ctx, "revoke other sessions", accountID, keep, reason)
}

// revokeAccount revokes the account's live sessions but keep (none when it is the nil uuid) for
// reason, and returns how many.
func (r *Sessions) revokeAccount(ctx context.Context, op string, accountID, keep uuid.UUID, reason session.RevokeReason) (int, error) {
	t := txFrom(ctx)
	if t == nil {
		return 0, fmt.Errorf("%s: %w", op, ErrNoTransaction)
	}
	if t.account(accountID) == nil {
		return 0, fmt.Errorf("%s: %w", op, ErrLockOrder)
	}
	res, err := t.tx.ExecContext(ctx, "UPDATE sessions s SET revoked_at = now(), revoke_reason = ? "+
		"WHERE s.account_id = ? AND s.id <> ? AND "+sessionLive, reason, accountID, keep)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return int(n), nil
}

// ListLive implements app.Sessions.
func (r *Sessions) ListLive(ctx context.Context, accountID uuid.UUID) ([]session.Session, error) {
	rows, err := Conn(ctx, r.db).QueryContext(ctx, "SELECT "+sessionColumns+" FROM sessions s "+
		"WHERE s.account_id = ? AND "+sessionLive+" ORDER BY s.created_at DESC, s.id DESC", accountID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []session.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("list sessions: %w", err)
		}
		list = append(list, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return list, nil
}

// EraseSuccessors implements app.Sessions. It reads the partial index refresh_tokens_successor;
// a token it leaves is one tokenInGrace may still find in grace (I-13).
func (r *Sessions) EraseSuccessors(ctx context.Context, grace time.Duration) (int64, error) {
	res, err := Conn(ctx, r.db).ExecContext(ctx, `UPDATE refresh_tokens SET successor_enc = NULL
		WHERE successor_enc IS NOT NULL AND rotated_at < now() - ? * interval '1 microsecond'`, micros(grace))
	if err != nil {
		return 0, fmt.Errorf("erase refresh successors: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("erase refresh successors: %w", err)
	}
	return n, nil
}
