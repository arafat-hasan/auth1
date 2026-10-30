package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

var _ app.Flows = (*postgres.Flows)(nil)

// defaultWindows are L-7's defaults: 1 send per 60 s, 5 per hour.
var defaultWindows = app.SendWindows{Short: time.Minute, Long: time.Hour}

// sharedEmail opens n pending accounts that hold one email, unverified, each with a registration
// flow and a challenge to it.
func (e *flowsEnv) sharedEmail(t *testing.T, n int, email string) ([]flow.NewFlow, []flow.NewChallengeRecord) {
	t.Helper()
	var (
		fs []flow.NewFlow
		cs []flow.NewChallengeRecord
	)
	for i := range n {
		a := e.newAccount("", email)
		e.create(t, a)
		f := e.newFlow(a.ID, flow.KindRegistration, handle(fmt.Sprintf("%s %d", email, i)))
		e.open(t, f)
		c := e.otpChallenge(f.ID, a.Identifiers[0].ID, email, "123456")
		e.openChallenges(t, f, c)
		fs, cs = append(fs, f), append(cs, c)
	}
	return fs, cs
}

// trySend checks the limits for the email in f's transaction and records a send of c when they
// allow it (1 per short window, 5 per long one). It reports whether it sent.
func (e *flowsEnv) trySend(t *testing.T, f flow.NewFlow, c flow.NewChallengeRecord, email string) bool {
	t.Helper()
	return e.trySendAfter(t, f, c, email, func() {})
}

// trySendAfter is trySend, calling counted between the check and the send.
func (e *flowsEnv) trySendAfter(t *testing.T, f flow.NewFlow, c flow.NewChallengeRecord, email string, counted func()) bool {
	t.Helper()
	sent := false
	err := e.withChallenges(t, f, func(ctx context.Context, _ []flow.ChallengeRecord) error {
		n, err := e.flows.SendCounts(ctx, "email", email, defaultWindows)
		counted()
		if err != nil || n.Short >= 1 || n.Long >= 5 {
			return err
		}
		_, err = e.flows.RecordSend(ctx, c.ID)
		sent = err == nil
		return err
	})
	if err != nil {
		t.Error(err)
	}
	return sent
}

// totalSends returns the sends of every challenge to the email's blind index.
func (e *flowsEnv) totalSends(t *testing.T, email string) (total, challenges int) {
	t.Helper()
	bidx, err := e.bidx.Compute("email", []byte(email))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.su.QueryRowContext(t.Context(),
		"SELECT coalesce(sum(sends), 0), count(*) FILTER (WHERE sends > 0) FROM challenges WHERE target_bidx = ?",
		bidx).Scan(&total, &challenges); err != nil {
		t.Fatal(err)
	}
	return total, challenges
}

// TestT20SharedSendBudget checks T-20 at the repository: ten pending accounts with one email
// share one send budget (I-21).
func TestT20SharedSendBudget(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	const email = "shared@example.org"
	fs, cs := e.sharedEmail(t, 10, email)

	// One send per minute across all ten.
	sent := 0
	for i := range fs {
		if e.trySend(t, fs[i], cs[i], email) {
			sent++
		}
	}
	if sent != 1 {
		t.Fatalf("first minute: %d sends, want 1", sent)
	}
	// Each later minute, a different account tries first; five sends an hour in all.
	for round := 1; round <= 6; round++ {
		e.exec(t, "UPDATE challenges SET last_sent_at = last_sent_at - interval '2 minutes' WHERE last_sent_at IS NOT NULL")
		for k := range fs {
			i := (round + k) % len(fs)
			e.trySend(t, fs[i], cs[i], email)
		}
	}
	if total, challenges := e.totalSends(t, email); total != 5 || challenges < 2 {
		t.Errorf("sends %d over %d challenges, want 5 over several", total, challenges)
	}
}

// TestSendCountsConcurrent checks that a check and a send to one address, made in parallel by
// different accounts, are exact: one send passes a one-per-window limit. Each transaction waits
// after its check for the others to check too, or for a short while when they cannot: without
// the address lock, every check would see no send.
func TestSendCountsConcurrent(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	const email = "race@example.org"
	fs, cs := e.sharedEmail(t, 10, email)
	var (
		wg      sync.WaitGroup
		arrived sync.WaitGroup
		all     = make(chan struct{})
	)
	arrived.Add(len(fs))
	go func() { arrived.Wait(); close(all) }()
	rendezvous := func() {
		arrived.Done()
		select {
		case <-all:
		case <-time.After(200 * time.Millisecond):
		}
	}
	for i := range fs {
		wg.Go(func() { e.trySendAfter(t, fs[i], cs[i], email, rendezvous) })
	}
	wg.Wait()
	if total, _ := e.totalSends(t, email); total != 1 {
		t.Errorf("sends %d, want 1", total)
	}
}

// TestSendCountsWindows checks the windows are the caller's and are read on last_sent_at, so a
// challenge opened long ago and sent recently counts.
func TestSendCountsWindows(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	const email = "windows@example.org"
	fs, cs := e.sharedEmail(t, 2, email)
	_, others := e.sharedEmail(t, 1, "other@example.org")
	e.exec(t, "UPDATE challenges SET sends = 3, last_sent_at = now() - interval '90 seconds' WHERE id = ?", cs[0].ID)
	e.exec(t, `UPDATE challenges SET sends = 1, last_sent_at = now() - interval '30 seconds',
		created_at = now() - interval '2 hours' WHERE id = ?`, cs[1].ID)
	e.exec(t, "UPDATE challenges SET sends = 4, last_sent_at = now() WHERE id = ?", others[0].ID)

	for _, c := range []struct {
		w    app.SendWindows
		want app.SendCounts
	}{
		{defaultWindows, app.SendCounts{Short: 1, Long: 4}},
		{app.SendWindows{Short: 2 * time.Minute, Long: time.Hour}, app.SendCounts{Short: 2, Long: 4}},
		{app.SendWindows{Short: 10 * time.Second, Long: time.Minute}, app.SendCounts{Short: 0, Long: 1}},
		{app.SendWindows{Short: 10 * time.Second, Long: 20 * time.Second}, app.SendCounts{}},
	} {
		var got app.SendCounts
		err := e.withChallenges(t, fs[0], func(ctx context.Context, _ []flow.ChallengeRecord) error {
			var err error
			got, err = e.flows.SendCounts(ctx, "email", email, c.w)
			return err
		})
		if err != nil || got != c.want {
			t.Errorf("SendCounts(%v) = %+v, %v; want %+v", c.w, got, err, c.want)
		}
	}

	if _, err := e.flows.SendCounts(t.Context(), "email", email, defaultWindows); !errors.Is(err, postgres.ErrNoTransaction) {
		t.Errorf("outside a transaction: %v, want ErrNoTransaction", err)
	}
	for _, w := range []app.SendWindows{{Short: time.Hour, Long: time.Minute}, {Short: 0, Long: time.Hour}} {
		err := e.uow.Do(t.Context(), func(ctx context.Context) error {
			_, err := e.flows.SendCounts(ctx, "email", email, w)
			return err
		})
		if err == nil {
			t.Errorf("SendCounts(%v) accepted", w)
		}
	}
}

// TestExhaustedSince checks the L-9 cooldown query: only challenges to the address closed
// unconsumed with their attempts used up, within the window.
func TestExhaustedSince(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	const email = "cool@example.org"
	_, cs := e.sharedEmail(t, 5, email)
	exhausted, consumed, expired, open, old := cs[0], cs[1], cs[2], cs[3], cs[4]
	e.exec(t, "UPDATE challenges SET attempts = 3, closed_at = now() - interval '5 minutes', secret = NULL WHERE id = ?", exhausted.ID)
	e.exec(t, "UPDATE challenges SET attempts = 3, closed_at = now() - interval '1 minute', consumed_at = now() - interval '1 minute', secret = NULL WHERE id = ?", consumed.ID)
	e.exec(t, "UPDATE challenges SET attempts = 2, closed_at = now() - interval '1 minute', secret = NULL WHERE id = ?", expired.ID)
	e.exec(t, "UPDATE challenges SET attempts = 2 WHERE id = ?", open.ID)
	e.exec(t, "UPDATE challenges SET attempts = 3, closed_at = now() - interval '20 minutes', secret = NULL WHERE id = ?", old.ID)

	var want time.Time
	if err := e.su.QueryRowContext(t.Context(), "SELECT closed_at FROM challenges WHERE id = ?", exhausted.ID).Scan(&want); err != nil {
		t.Fatal(err)
	}
	got, err := e.flows.ExhaustedSince(t.Context(), "email", email, 15*time.Minute)
	if err != nil || got == nil || !got.Equal(want) {
		t.Errorf("ExhaustedSince(15m) = %v, %v; want %v", got, err, want)
	}
	if got, err := e.flows.ExhaustedSince(t.Context(), "email", email, 2*time.Minute); err != nil || got != nil {
		t.Errorf("ExhaustedSince(2m) = %v, %v; want nil", got, err)
	}
	if got, err := e.flows.ExhaustedSince(t.Context(), "email", "else@example.org", time.Hour); err != nil || got != nil {
		t.Errorf("another address: %v, %v; want nil", got, err)
	}
}
