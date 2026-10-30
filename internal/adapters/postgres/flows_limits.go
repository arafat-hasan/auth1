package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/arafat-hasan/auth1/internal/app"
)

// errSendWindows is a SendWindows with a short window that is not positive or longer than the
// long one: a configuration fault the caller passed on.
var errSendWindows = errors.New("postgres: send windows invalid")

// SendCounts implements app.Flows (TDD-07 §5). The advisory lock, keyed on the blind index,
// serialises the check-then-send of every transaction sending to the address, so the limit is
// exact. It is taken after the account, flow and challenge locks and held to the end of the
// transaction; a use case sending to several addresses checks them in one order, by type.
// Both windows are read on last_sent_at, so a challenge opened long ago and resent recently
// counts; Long counts every send of a challenge last sent within it.
func (r *Flows) SendCounts(ctx context.Context, targetType, value string, w app.SendWindows) (app.SendCounts, error) {
	t := txFrom(ctx)
	if t == nil {
		return app.SendCounts{}, fmt.Errorf("count sends: %w", ErrNoTransaction)
	}
	if w.Short <= 0 || w.Short > w.Long {
		return app.SendCounts{}, fmt.Errorf("count sends: %w", errSendWindows)
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
		SELECT count(*) FILTER (WHERE last_sent_at > now() - make_interval(secs => ?)),
		       coalesce(sum(sends), 0)
		FROM challenges
		WHERE target_bidx = ? AND last_sent_at > now() - make_interval(secs => ?)`,
		w.Short.Seconds(), bidx, w.Long.Seconds()).Scan(&n.Short, &n.Long)
	if err != nil {
		return app.SendCounts{}, fmt.Errorf("count sends: %w", err)
	}
	return n, nil
}

// ExhaustedSince implements app.Flows (L-9). Exhausted is what flow.Challenge.End calls it: no
// close reason is stored, so a challenge closed unconsumed with its attempts used up.
func (r *Flows) ExhaustedSince(ctx context.Context, targetType, value string, within time.Duration) (*time.Time, error) {
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
