package postgres_test

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// challengeFlow opens a registration flow with one 3-attempt OTP challenge and returns both.
func (e *flowsEnv) challengeFlow(t *testing.T, name string) (flow.NewFlow, flow.NewChallengeRecord) {
	t.Helper()
	acc := e.flowAccount(t)
	idID, email := e.identifierOf(t, acc)
	f := e.newFlow(acc, flow.KindRegistration, handle(name))
	e.open(t, f)
	c := e.otpChallenge(f.ID, idID, email, "123456")
	e.openChallenges(t, f, c)
	return f, c
}

// challengeCols reads raw columns of the challenge as superuser.
func (e *flowsEnv) challengeCols(t *testing.T, id uuid.UUID) (attempts, sends int, closed, consumed, secret bool) {
	t.Helper()
	err := e.su.QueryRowContext(t.Context(), `
		SELECT attempts, sends, closed_at IS NOT NULL, consumed_at IS NOT NULL, secret IS NOT NULL
		FROM challenges WHERE id = ?`, id).Scan(&attempts, &sends, &closed, &consumed, &secret)
	if err != nil {
		t.Fatal(err)
	}
	return attempts, sends, closed, consumed, secret
}

// TestAttemptConcurrent checks I-4 under concurrency: ten parallel wrong attempts on a 3-attempt
// challenge record exactly three.
func TestAttemptConcurrent(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	f, c := e.challengeFlow(t, "a")

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted []int
	)
	for range 10 {
		wg.Go(func() {
			err := e.withChallenges(t, f, func(ctx context.Context, _ []flow.ChallengeRecord) error {
				n, ok, err := e.flows.Attempt(ctx, c.ID)
				if ok {
					mu.Lock()
					accepted = append(accepted, n)
					mu.Unlock()
				}
				return err
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if len(accepted) != 3 {
		t.Errorf("accepted attempts %v, want 3", accepted)
	}
	if attempts, _, _, _, _ := e.challengeCols(t, c.ID); attempts != 3 {
		t.Errorf("stored attempts %d, want 3", attempts)
	}
}

// TestAttemptClosed checks that a closed challenge counts no attempt.
func TestAttemptClosed(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	f, c := e.challengeFlow(t, "a")
	err := e.withChallenges(t, f, func(ctx context.Context, _ []flow.ChallengeRecord) error {
		if n, ok, err := e.flows.Attempt(ctx, c.ID); err != nil || !ok || n != 1 {
			t.Errorf("open: Attempt = %d, %v, %v; want 1, true", n, ok, err)
		}
		if ok, err := e.flows.CloseChallenge(ctx, c.ID, false); err != nil || !ok {
			t.Fatalf("CloseChallenge = %v, %v", ok, err)
		}
		if n, ok, err := e.flows.Attempt(ctx, c.ID); err != nil || ok || n != 0 {
			t.Errorf("closed: Attempt = %d, %v, %v; want 0, false", n, ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts, _, _, _, _ := e.challengeCols(t, c.ID); attempts != 1 {
		t.Errorf("stored attempts %d, want 1", attempts)
	}
}

// TestConsumeOnce checks I-4's other half: a challenge is consumed at most once.
func TestConsumeOnce(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	f, c := e.challengeFlow(t, "a")
	var first, second bool
	err := e.withChallenges(t, f, func(ctx context.Context, _ []flow.ChallengeRecord) error {
		var err error
		first, err = e.flows.CloseChallenge(ctx, c.ID, true)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var consumedAt, after any
	if err := e.su.QueryRowContext(t.Context(), "SELECT consumed_at FROM challenges WHERE id = ?", c.ID).Scan(&consumedAt); err != nil {
		t.Fatal(err)
	}
	err = e.withChallenges(t, f, func(ctx context.Context, _ []flow.ChallengeRecord) error {
		var err error
		second, err = e.flows.CloseChallenge(ctx, c.ID, true)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.su.QueryRowContext(t.Context(), "SELECT consumed_at FROM challenges WHERE id = ?", c.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !first || second {
		t.Errorf("CloseChallenge = %v then %v, want true then false", first, second)
	}
	if consumedAt == nil || consumedAt != after {
		t.Errorf("consumed_at %v then %v", consumedAt, after)
	}
}

func TestRecordSend(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	f, c := e.challengeFlow(t, "a")
	err := e.withChallenges(t, f, func(ctx context.Context, cs []flow.ChallengeRecord) error {
		if cs[0].LastSentAt != nil {
			t.Errorf("LastSentAt before a send: %v", cs[0].LastSentAt)
		}
		for want := 1; want <= 2; want++ {
			if n, err := e.flows.RecordSend(ctx, c.ID); err != nil || n != want {
				t.Errorf("RecordSend = %d, %v; want %d", n, err, want)
			}
		}
		if _, err := e.flows.CloseChallenge(ctx, c.ID, false); err != nil {
			return err
		}
		_, err := e.flows.RecordSend(ctx, c.ID)
		checkCode(t, err, domain.CodeNotFound)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = e.withChallenges(t, f, func(_ context.Context, cs []flow.ChallengeRecord) error {
		if cs[0].Sends != 2 || cs[0].LastSentAt == nil {
			t.Errorf("after sends: sends %d, last_sent_at %v", cs[0].Sends, cs[0].LastSentAt)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var sends []string
	rows, err := e.su.QueryContext(t.Context(), `
		SELECT s.send || ' ' || (s.target_bidx = c.target_bidx) || ' ' || (s.sent_at = c.last_sent_at)
		FROM challenge_sends s JOIN challenges c ON c.id = s.challenge_id
		WHERE s.challenge_id = ? ORDER BY s.send`, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		sends = append(sends, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"1 true true", "2 true true"}; !slices.Equal(sends, want) {
		t.Errorf("challenge_sends rows %q, want %q", sends, want)
	}
}

// TestClosedHoldsNoSecret checks I-5 for every way a challenge or a flow closes: the secret and
// the pending secret are gone in the statement that closes them.
func TestClosedHoldsNoSecret(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	closeBy := map[string]func(ctx context.Context, f flow.NewFlow, c flow.NewChallengeRecord) error{
		"consumed": func(ctx context.Context, _ flow.NewFlow, c flow.NewChallengeRecord) error {
			_, err := e.flows.CloseChallenge(ctx, c.ID, true)
			return err
		},
		"unconsumed": func(ctx context.Context, _ flow.NewFlow, c flow.NewChallengeRecord) error {
			_, err := e.flows.CloseChallenge(ctx, c.ID, false)
			return err
		},
		"flow completed": func(ctx context.Context, f flow.NewFlow, _ flow.NewChallengeRecord) error {
			return e.flows.Complete(ctx, f.ID)
		},
		"flow cancelled": func(ctx context.Context, f flow.NewFlow, _ flow.NewChallengeRecord) error {
			return e.flows.Cancel(ctx, f.ID, flow.CloseExpired)
		},
		"flow replaced": func(ctx context.Context, f flow.NewFlow, _ flow.NewChallengeRecord) error {
			return e.flows.Open(ctx, e.newFlow(f.AccountID, flow.KindRegistration, handle("replacement")))
		},
	}
	for name, closeIt := range closeBy {
		f, c := e.challengeFlow(t, name)
		err := e.withChallenges(t, f, func(ctx context.Context, _ []flow.ChallengeRecord) error {
			return closeIt(ctx, f, c)
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, _, closed, _, secret := e.challengeCols(t, c.ID); !closed || secret {
			t.Errorf("%s: challenge closed %v, holds secret %v", name, closed, secret)
		}
	}

	// A closing flow erases its pending secret.
	for _, reason := range []string{"completed", "cancelled"} {
		f := e.newFlow(e.flowAccount(t), flow.KindTOTPReplacement, handle("totp "+reason))
		f.PendingSecret = flow.Secret("PENDINGTOTPSECRET")
		e.open(t, f)
		e.locked(t, f, func(ctx context.Context, lf flow.Flow) error {
			if reason == "completed" {
				return e.flows.Complete(ctx, lf.ID)
			}
			return e.flows.Cancel(ctx, lf.ID, flow.CloseAccountClosed)
		})
		if _, _, _, pending := e.flowCols(t, f.ID); pending != nil {
			t.Errorf("%s flow holds its pending secret", reason)
		}
	}
}
