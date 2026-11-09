package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// SignInThrottles implements app.SignInThrottles on sign_in_throttles (TDD-07 §4), and reads the
// devices of sessions for KnownDevice.
type SignInThrottles struct {
	db *bun.DB
}

// NewSignInThrottles returns the repository on db.
func NewSignInThrottles(db *bun.DB) *SignInThrottles {
	return &SignInThrottles{db: db}
}

// Delay implements app.SignInThrottles.
func (r *SignInThrottles) Delay(ctx context.Context, accountID uuid.UUID, bucket account.Bucket) (time.Duration, error) {
	var us int64
	if err := Conn(ctx, r.db).QueryRowContext(ctx, `
		SELECT coalesce(max(ceil(extract(epoch FROM delay_until - now()) * 1000000)), 0)::bigint
		FROM sign_in_throttles WHERE account_id = ? AND bucket = ? AND delay_until > now()`,
		accountID, string(bucket)).Scan(&us); err != nil {
		return 0, fmt.Errorf("read sign-in delay: %w", err)
	}
	return time.Duration(us) * time.Microsecond, nil
}

// Fail implements app.SignInThrottles. The upsert counts the failure and keeps the row locked
// until the transaction ends, so the delay the second statement sets is the one for that count,
// and no concurrent failure is lost.
func (r *SignInThrottles) Fail(ctx context.Context, accountID uuid.UUID, bucket account.Bucket, p account.ThrottlePolicy) (int, error) {
	t := txFrom(ctx)
	if t == nil {
		return 0, fmt.Errorf("count sign-in failure: %w", ErrNoTransaction)
	}
	var n int
	if err := t.tx.QueryRowContext(ctx, `
		INSERT INTO sign_in_throttles AS t (account_id, bucket, failures, updated_at) VALUES (?, ?, 1, now())
		ON CONFLICT (account_id, bucket) DO UPDATE SET failures = t.failures + 1, updated_at = now()
		RETURNING failures`, accountID, string(bucket)).Scan(&n); err != nil {
		return 0, fmt.Errorf("count sign-in failure: %w", err)
	}
	if d := p.Delay(n); d > 0 {
		if _, err := t.tx.ExecContext(ctx, `
			UPDATE sign_in_throttles SET delay_until = now() + ? * interval '1 microsecond'
			WHERE account_id = ? AND bucket = ?`, micros(d), accountID, string(bucket)); err != nil {
			return 0, fmt.Errorf("set sign-in delay: %w", err)
		}
	}
	return n, nil
}

// Reset implements app.SignInThrottles.
func (r *SignInThrottles) Reset(ctx context.Context, accountID uuid.UUID, bucket account.Bucket) error {
	return r.clear(ctx, "reset sign-in bucket", accountID, "AND bucket = ?", string(bucket))
}

// ResetAll implements app.SignInThrottles.
func (r *SignInThrottles) ResetAll(ctx context.Context, accountID uuid.UUID) error {
	return r.clear(ctx, "reset sign-in buckets", accountID, "")
}

// clear deletes the account's throttle rows that match cond, under the account lock.
func (r *SignInThrottles) clear(ctx context.Context, op string, accountID uuid.UUID, cond string, args ...any) error {
	t := txFrom(ctx)
	if t == nil {
		return fmt.Errorf("%s: %w", op, ErrNoTransaction)
	}
	if t.account(accountID) == nil {
		return fmt.Errorf("%s: %w", op, ErrLockOrder)
	}
	if _, err := t.tx.ExecContext(ctx, "DELETE FROM sign_in_throttles WHERE account_id = ? "+cond,
		append([]any{accountID}, args...)...); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// KnownDevice implements app.SignInThrottles. A session ended when it was revoked, or else at the
// earlier of its expiries; a live one ends in the future.
func (r *SignInThrottles) KnownDevice(ctx context.Context, accountID, deviceID uuid.UUID, within time.Duration) (bool, error) {
	var known bool
	if err := Conn(ctx, r.db).QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM sessions WHERE account_id = ? AND device_id = ?
			AND coalesce(revoked_at, least(idle_expires_at, absolute_expires_at)) > now() - ? * interval '1 microsecond')`,
		accountID, deviceID, micros(within)).Scan(&known); err != nil {
		return false, fmt.Errorf("read known device: %w", err)
	}
	return known, nil
}
