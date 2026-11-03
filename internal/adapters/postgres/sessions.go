package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/session"
)

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

// FindToken implements app.Sessions.
func (r *Sessions) FindToken(ctx context.Context, tokenHash []byte, grace time.Duration) (session.Token, session.Session, error) {
	t := txFrom(ctx)
	if t == nil {
		return session.Token{}, session.Session{}, fmt.Errorf("find refresh token: %w", ErrNoTransaction)
	}
	var (
		tok     session.Token
		rotated sql.NullTime
	)
	s, err := scanSession(t.tx.QueryRowContext(ctx, "SELECT "+sessionColumns+`,
			r.token_hash, r.issued_at, r.rotated_at,
			(r.rotated_at IS NOT NULL AND r.successor_enc IS NOT NULL
				AND now() - r.rotated_at <= ? * interval '1 microsecond')
		FROM refresh_tokens r JOIN sessions s ON s.id = r.session_id
		WHERE r.token_hash = ?
		FOR UPDATE OF s`, micros(grace), tokenHash),
		&tok.Hash, &tok.IssuedAt, &rotated, &tok.InGrace)
	if errors.Is(err, sql.ErrNoRows) {
		return session.Token{}, session.Session{}, sessionInvalid()
	}
	if err != nil {
		return session.Token{}, session.Session{}, fmt.Errorf("find refresh token: %w", err)
	}
	t.lockSession(s.ID)
	tok.SessionID, tok.IssuedAt, tok.RotatedAt = s.ID, tok.IssuedAt.UTC(), timePtr(rotated)
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
