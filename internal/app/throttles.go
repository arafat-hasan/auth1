package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// SignInThrottles is the repository of sign_in_throttles (TDD-07 §4, L-3): failed sign-ins and
// their delay per account × bucket, in PostgreSQL, so the delays hold without Redis (T-16). Every
// time it stores or compares is the database's now().
//
// In the lock order (G-5, TDD-01 §4.2) a throttle row comes right after its account row. A failed
// sign-in locks only its throttle row, through Fail, and not the account, so it moves no version;
// Reset and ResetAll run under the account lock.
type SignInThrottles interface {
	// Delay returns how long the bucket of the account is still delayed, 0 when it is not. It
	// locks nothing.
	Delay(ctx context.Context, accountID uuid.UUID, bucket account.Bucket) (time.Duration, error)
	// Fail counts one more failure in the bucket of the account and, when p.Delay(failures) is
	// above 0, sets its delay to now + that, returning the failures counted. Concurrent failures are each counted.
	// It runs inside UnitOfWork.Do; it needs no account lock.
	Fail(ctx context.Context, accountID uuid.UUID, bucket account.Bucket, p account.ThrottlePolicy) (int, error)
	// Reset clears the bucket of the account after a success. The account must be locked.
	Reset(ctx context.Context, accountID uuid.UUID, bucket account.Bucket) error
	// ResetAll clears every bucket of the account (a password reset). The account must be locked.
	ResetAll(ctx context.Context, accountID uuid.UUID) error
	// KnownDevice reports whether deviceID is on one of the account's sessions that is live or
	// ended (revoked or expired) less than within ago. It locks nothing.
	KnownDevice(ctx context.Context, accountID, deviceID uuid.UUID, within time.Duration) (bool, error)
}
