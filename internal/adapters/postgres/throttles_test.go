package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

var _ app.SignInThrottles = (*postgres.SignInThrottles)(nil)

// throttlePolicy is L-3's shape with minute-scale delays, so no assertion depends on how fast the
// statements run: from the 5th failure, 1 min doubling to 15 min.
var throttlePolicy = account.ThrottlePolicy{Threshold: 5, FirstDelay: time.Minute, MaxDelay: 15 * time.Minute}

// throttlesEnv is the throttles repository beside the sessions one, on one database.
type throttlesEnv struct {
	*sessionsEnv
	throttles *postgres.SignInThrottles
}

func throttlesDB(t *testing.T) *throttlesEnv {
	t.Helper()
	e := sessionsDB(t)
	return &throttlesEnv{sessionsEnv: e, throttles: postgres.NewSignInThrottles(e.app)}
}

// fail counts one failure in its own transaction, without the account lock.
func (e *throttlesEnv) fail(t *testing.T, id uuid.UUID, b account.Bucket) int {
	t.Helper()
	var n int
	e.do(t, func(ctx context.Context) error {
		var err error
		n, err = e.throttles.Fail(ctx, id, b, throttlePolicy)
		return err
	})
	return n
}

func (e *throttlesEnv) delay(t *testing.T, id uuid.UUID, b account.Bucket) time.Duration {
	t.Helper()
	d, err := e.throttles.Delay(t.Context(), id, b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestThrottlesFailSetsDelay(t *testing.T) {
	t.Parallel()
	e := throttlesDB(t)
	id := e.sessionAccount(t)
	for i := 1; i <= 4; i++ {
		if n := e.fail(t, id, account.UntrustedBucket); n != i {
			t.Fatalf("failure %d counted as %d", i, n)
		}
		if d := e.delay(t, id, account.UntrustedBucket); d != 0 {
			t.Fatalf("delay after %d failures = %v, want 0", i, d)
		}
	}
	e.fail(t, id, account.UntrustedBucket)
	if d := e.delay(t, id, account.UntrustedBucket); d <= 50*time.Second || d > time.Minute {
		t.Errorf("delay after 5 failures = %v, want just under 1 min", d)
	}
	e.fail(t, id, account.UntrustedBucket)
	if d := e.delay(t, id, account.UntrustedBucket); d <= 110*time.Second || d > 2*time.Minute {
		t.Errorf("delay after 6 failures = %v, want just under 2 min", d)
	}
	if _, err := e.su.ExecContext(t.Context(),
		"UPDATE sign_in_throttles SET delay_until = now() - interval '1 second' WHERE account_id = ?", id); err != nil {
		t.Fatal(err)
	}
	if d := e.delay(t, id, account.UntrustedBucket); d != 0 {
		t.Errorf("delay past delay_until = %v, want 0", d)
	}
}

// TestThrottlesFailCountsEveryFailure fails if Fail reads the count and writes it back in two
// statements without the row lock: concurrent failures would then be lost.
func TestThrottlesFailCountsEveryFailure(t *testing.T) {
	t.Parallel()
	e := throttlesDB(t)
	id := e.sessionAccount(t)
	const n = 20
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if err := e.uow.Do(t.Context(), func(ctx context.Context) error {
				_, err := e.throttles.Fail(ctx, id, account.UntrustedBucket, throttlePolicy)
				return err
			}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := e.fail(t, id, account.UntrustedBucket); got != n+1 {
		t.Errorf("failures after %d concurrent and one more = %d, want %d", n, got, n+1)
	}
}

// TestThrottlesFailWaitsForTheFirst is the deterministic form of the test above: a second Fail
// in another transaction waits on the row until the first commits, then counts on top of it.
func TestThrottlesFailWaitsForTheFirst(t *testing.T) {
	t.Parallel()
	e := throttlesDB(t)
	id := e.sessionAccount(t)
	counted, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- e.uow.Do(t.Context(), func(ctx context.Context) error {
			if _, err := e.throttles.Fail(ctx, id, account.UntrustedBucket, throttlePolicy); err != nil {
				return err
			}
			close(counted)
			<-release
			return nil
		})
	}()
	<-counted
	type result struct {
		n   int
		err error
	}
	second := make(chan result, 1)
	go func() {
		var r result
		r.err = e.uow.Do(t.Context(), func(ctx context.Context) error {
			var err error
			r.n, err = e.throttles.Fail(ctx, id, account.UntrustedBucket, throttlePolicy)
			return err
		})
		second <- r
	}()
	select {
	case r := <-second:
		close(release)
		t.Fatalf("the second Fail returned %d, %v before the first committed", r.n, r.err)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if r := <-second; r.err != nil || r.n != 2 {
		t.Errorf("second Fail = %d, %v; want 2", r.n, r.err)
	}
}

// TestThrottlesBucketsApart is T-34 at the repository: failures in one bucket leave the others.
func TestThrottlesBucketsApart(t *testing.T) {
	t.Parallel()
	e := throttlesDB(t)
	id, other := e.sessionAccount(t), e.sessionAccount(t)
	device := account.DeviceBucket(e.ids.New())
	for range 8 {
		e.fail(t, id, account.UntrustedBucket)
	}
	if d := e.delay(t, id, device); d != 0 {
		t.Errorf("device bucket delay = %v, want 0", d)
	}
	if d := e.delay(t, other, account.UntrustedBucket); d != 0 {
		t.Errorf("another account's delay = %v, want 0", d)
	}
	if n := e.fail(t, id, device); n != 1 {
		t.Errorf("device bucket failures = %d, want 1", n)
	}
}

func TestThrottlesReset(t *testing.T) {
	t.Parallel()
	e := throttlesDB(t)
	id := e.sessionAccount(t)
	device := account.DeviceBucket(e.ids.New())
	for range 6 {
		e.fail(t, id, account.UntrustedBucket)
		e.fail(t, id, device)
	}
	e.do(t, func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, id); err != nil {
			return err
		}
		return e.throttles.Reset(ctx, id, account.UntrustedBucket)
	})
	if d := e.delay(t, id, account.UntrustedBucket); d != 0 {
		t.Errorf("reset bucket delay = %v, want 0", d)
	}
	if n := e.fail(t, id, account.UntrustedBucket); n != 1 {
		t.Errorf("failures after reset = %d, want 1", n)
	}
	if d := e.delay(t, id, device); d == 0 {
		t.Error("Reset cleared another bucket")
	}
	e.do(t, func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, id); err != nil {
			return err
		}
		return e.throttles.ResetAll(ctx, id)
	})
	if d := e.delay(t, id, device); d != 0 {
		t.Errorf("delay after ResetAll = %v, want 0", d)
	}
}

func TestThrottlesLocks(t *testing.T) {
	t.Parallel()
	e := throttlesDB(t)
	id := e.sessionAccount(t)
	if _, err := e.throttles.Fail(t.Context(), id, account.UntrustedBucket, throttlePolicy); !errors.Is(err, postgres.ErrNoTransaction) {
		t.Errorf("Fail outside Do: %v, want ErrNoTransaction", err)
	}
	for name, f := range map[string]func(context.Context) error{
		"Reset":    func(ctx context.Context) error { return e.throttles.Reset(ctx, id, account.UntrustedBucket) },
		"ResetAll": func(ctx context.Context) error { return e.throttles.ResetAll(ctx, id) },
	} {
		err := e.uow.Do(t.Context(), f)
		if !errors.Is(err, postgres.ErrLockOrder) {
			t.Errorf("%s without the account lock: %v, want ErrLockOrder", name, err)
		}
	}
}

func TestKnownDevice(t *testing.T) {
	t.Parallel()
	e := throttlesDB(t)
	const within = 90 * 24 * time.Hour
	id, other := e.sessionAccount(t), e.sessionAccount(t)
	session := func(account uuid.UUID, name, ended string) uuid.UUID {
		s := e.newSession(account)
		e.createSession(t, s, name)
		if ended != "" {
			if _, err := e.su.ExecContext(t.Context(), "UPDATE sessions SET "+ended+" WHERE id = ?", s.ID); err != nil {
				t.Fatal(err)
			}
		}
		return *s.DeviceID
	}
	live := session(id, "live", "")
	revokedRecently := session(id, "revoked89", "revoked_at = now() - interval '89 days', revoke_reason = 'signed_out'")
	revokedLong := session(id, "revoked91", "revoked_at = now() - interval '91 days', revoke_reason = 'signed_out'")
	expiredRecently := session(id, "expired89", "idle_expires_at = now() - interval '89 days'")
	expiredLong := session(id, "expired91", "idle_expires_at = now() - interval '91 days', absolute_expires_at = now() - interval '91 days'")
	others := session(other, "other", "")
	for _, tt := range []struct {
		name   string
		device uuid.UUID
		want   bool
	}{
		{"live", live, true},
		{"revoked 89 days ago", revokedRecently, true},
		{"revoked 91 days ago", revokedLong, false},
		{"expired 89 days ago", expiredRecently, true},
		{"expired 91 days ago", expiredLong, false},
		{"another account's", others, false},
		{"unknown", e.ids.New(), false},
	} {
		got, err := e.throttles.KnownDevice(t.Context(), id, tt.device, within)
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("%s: KnownDevice = %v, want %v", tt.name, got, tt.want)
		}
	}
}
