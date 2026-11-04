package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// expiredPendingRegistration is the condition of a registration or invitation flow of a pending
// account (TDD-02 §2.5 step 1), on flows f.
const expiredPendingRegistration = `f.kind IN ('registration', 'invitation')
	AND EXISTS (SELECT 1 FROM accounts a WHERE a.id = f.account_id AND a.status = 'pending')`

// ExpiredPending implements app.ExpiringFlows.
func (r *Flows) ExpiredPending(ctx context.Context, limit int) ([]flow.Flow, error) {
	rows, err := Conn(ctx, r.db).QueryContext(ctx, "SELECT "+flowColumns+" FROM flows f WHERE "+flowOpen+
		" AND f.expires_at <= now() AND "+expiredPendingRegistration+" ORDER BY f.expires_at, f.id LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("expired flows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []flow.Flow
	for rows.Next() {
		f, err := scanFlow(rows)
		if err != nil {
			return nil, fmt.Errorf("expired flows: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("expired flows: %w", err)
	}
	return out, nil
}

// LockExpired implements app.ExpiringFlows.
func (r *Flows) LockExpired(ctx context.Context, f flow.Flow) (flow.Flow, error) {
	t := txFrom(ctx)
	if t == nil {
		return flow.Flow{}, fmt.Errorf("lock expired flow: %w", ErrNoTransaction)
	}
	if t.account(f.AccountID) == nil {
		return flow.Flow{}, fmt.Errorf("lock expired flow: %w", ErrLockOrder)
	}
	got, err := scanFlow(t.tx.QueryRowContext(ctx, "SELECT "+flowColumns+" FROM flows f "+
		"WHERE f.id = ? AND f.account_id = ? AND "+flowOpen+" AND f.expires_at <= now() FOR UPDATE",
		f.ID, f.AccountID))
	if errors.Is(err, sql.ErrNoRows) {
		return flow.Flow{}, notFound("flow")
	}
	if err != nil {
		return flow.Flow{}, fmt.Errorf("lock expired flow: %w", err)
	}
	t.lockFlow(got.ID, got.Kind)
	return got, nil
}

// CloseExpired implements app.ExpiringFlows. The flows are taken FOR UPDATE SKIP LOCKED, and
// their challenges are updated only through them: every other writer of a challenge holds its
// flow's lock first (G-5), so the statement waits for nothing.
func (r *Flows) CloseExpired(ctx context.Context, limit int) (int, error) {
	var n int
	err := Conn(ctx, r.db).QueryRowContext(ctx, `
		WITH due AS (
			SELECT f.id FROM flows f
			WHERE `+flowOpen+` AND f.expires_at <= now() AND NOT (`+expiredPendingRegistration+`)
			ORDER BY f.expires_at, f.id LIMIT ?
			FOR UPDATE OF f SKIP LOCKED),
		f AS (
			UPDATE flows SET cancelled_at = now(), close_reason = 'expired', pending_secret = NULL
			WHERE id IN (SELECT id FROM due)
			RETURNING id),
		c AS (
			UPDATE challenges SET closed_at = now(), secret = NULL
			WHERE flow_id IN (SELECT id FROM f) AND closed_at IS NULL)
		SELECT count(*) FROM f`, limit).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("close expired flows: %w", err)
	}
	return n, nil
}

// CloseExpiredChallenges implements app.ExpiringFlows.
func (r *Flows) CloseExpiredChallenges(ctx context.Context, limit int) (int, error) {
	res, err := Conn(ctx, r.db).ExecContext(ctx, `
		UPDATE challenges SET closed_at = now(), secret = NULL
		WHERE id IN (
			SELECT id FROM challenges
			WHERE closed_at IS NULL AND expires_at <= now()
			ORDER BY expires_at, id LIMIT ?
			FOR UPDATE SKIP LOCKED)`, limit)
	if err != nil {
		return 0, fmt.Errorf("close expired challenges: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("close expired challenges: %w", err)
	}
	return int(n), nil
}
