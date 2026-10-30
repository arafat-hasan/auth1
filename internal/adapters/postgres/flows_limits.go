package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/arafat-hasan/auth1/internal/app"
)

// errWindow is a limit window that is not positive, or a SendWindows whose short window is longer
// than its long one: a configuration fault the caller passed on. It fails the check rather than
// skip it.
var errWindow = errors.New("postgres: limit window invalid")

// SendCounts implements app.Flows (TDD-07 §5). The advisory lock, keyed on the blind index,
// serialises the check-then-send of every transaction sending to the address, so the limit is
// exact. It is taken after the account, flow and challenge locks and held to the end of the
// transaction; a use case sending to several addresses checks them in one order, by type.
// It counts the rows of challenge_sends, one per send, so each window counts exactly the sends
// made within it, whenever their challenge was opened.
func (r *Flows) SendCounts(ctx context.Context, targetType, value string, w app.SendWindows) (app.SendCounts, error) {
	t := txFrom(ctx)
	if t == nil {
		return app.SendCounts{}, fmt.Errorf("count sends: %w", ErrNoTransaction)
	}
	if w.Short <= 0 || w.Short > w.Long {
		return app.SendCounts{}, fmt.Errorf("count sends: %w", errWindow)
	}
	bidx, err := r.bidx.Compute(targetType, []byte(value))
	if err != nil {
		return app.SendCounts{}, fmt.Errorf("count sends: %w", err)
	}
	if _, err := t.tx.ExecContext(ctx,
		"SELECT pg_advisory_xact_lock(hashtextextended(encode(?::bytea, 'hex'), 0))", bidx); err != nil {
		return app.SendCounts{}, fmt.Errorf("count sends: lock address: %w", err)
	}
	var n app.SendCounts
	err = t.tx.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE sent_at > now() - make_interval(secs => ?)), count(*)
		FROM challenge_sends
		WHERE target_bidx = ? AND sent_at > now() - make_interval(secs => ?)`,
		w.Short.Seconds(), bidx, w.Long.Seconds()).Scan(&n.Short, &n.Long)
	if err != nil {
		return app.SendCounts{}, fmt.Errorf("count sends: %w", err)
	}
	return n, nil
}

// ExhaustedSince implements app.Flows (L-9). Exhausted is what flow.Challenge.End calls it: no
// close reason is stored, so a challenge closed unconsumed with its attempts used up.
func (r *Flows) ExhaustedSince(ctx context.Context, targetType, value string, within time.Duration) (*time.Time, error) {
	if within <= 0 {
		return nil, fmt.Errorf("find exhausted challenge: %w", errWindow)
	}
	bidx, err := r.bidx.Compute(targetType, []byte(value))
	if err != nil {
		return nil, fmt.Errorf("find exhausted challenge: %w", err)
	}
	var closed sql.NullTime
	err = Conn(ctx, r.db).QueryRowContext(ctx, `
		SELECT max(closed_at) FROM challenges
		WHERE target_bidx = ? AND closed_at > now() - make_interval(secs => ?)
		  AND consumed_at IS NULL AND attempts >= max_attempts`,
		bidx, within.Seconds()).Scan(&closed)
	if err != nil {
		return nil, fmt.Errorf("find exhausted challenge: %w", err)
	}
	return timePtr(closed), nil
}
