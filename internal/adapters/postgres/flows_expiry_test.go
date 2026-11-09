package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

var _ app.ExpiringFlows = (*postgres.Flows)(nil)

// expire moves the flow's expiry, and its challenges', into the past, by ago seconds.
func (e *flowsEnv) expire(t *testing.T, flowID uuid.UUID, ago int) {
	t.Helper()
	e.exec(t, "UPDATE flows SET expires_at = now() - make_interval(secs => ?) WHERE id = ?", ago, flowID)
	e.exec(t, "UPDATE challenges SET expires_at = now() - make_interval(secs => ?) WHERE flow_id = ?", ago, flowID)
}

// openFlow opens a flow of kind on a new pending account, with one OTP challenge, and returns it.
func (e *flowsEnv) openFlow(t *testing.T, kind flow.Kind) flow.NewFlow {
	t.Helper()
	acc := e.flowAccount(t)
	f := e.newFlow(acc, kind, handle(uuid.NewString()))
	if kind == flow.KindInvitation {
		f.State = flow.InvitationState{PendingTypes: []string{"email"}}
	}
	e.open(t, f)
	idID, value := e.identifierOf(t, acc)
	e.openChallenges(t, f, e.otpChallenge(f.ID, idID, value, "123456"))
	return f
}

// version returns the account's version, read as superuser.
func (e *flowsEnv) version(t *testing.T, id uuid.UUID) int64 {
	t.Helper()
	var v int64
	if err := e.su.QueryRowContext(t.Context(), "SELECT version FROM accounts WHERE id = ?", id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// openSecrets counts the flow's challenges that are open or still hold a secret.
func (e *flowsEnv) openSecrets(t *testing.T, flowID uuid.UUID) (open, secrets int) {
	t.Helper()
	err := e.su.QueryRowContext(t.Context(), `
		SELECT count(*) FILTER (WHERE closed_at IS NULL), count(*) FILTER (WHERE secret IS NOT NULL)
		FROM challenges WHERE flow_id = ?`, flowID).Scan(&open, &secrets)
	if err != nil {
		t.Fatal(err)
	}
	return open, secrets
}

func flowIDs(fs []flow.Flow) []uuid.UUID {
	var ids []uuid.UUID
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestExpiredPendingSelects(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	older := e.openFlow(t, flow.KindRegistration)
	e.expire(t, older.ID, 120)
	newer := e.openFlow(t, flow.KindRegistration)
	e.expire(t, newer.ID, 60)
	e.openFlow(t, flow.KindRegistration) // live
	signIn := e.openFlow(t, flow.KindSignIn)
	e.expire(t, signIn.ID, 300)
	active := e.openFlow(t, flow.KindRegistration)
	e.expire(t, active.ID, 300)
	e.do(t, func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, active.AccountID); err != nil {
			return err
		}
		return e.repo.Activate(ctx, active.AccountID)
	})
	closed := e.openFlow(t, flow.KindRegistration)
	e.locked(t, closed, func(ctx context.Context, f flow.Flow) error { return e.flows.Complete(ctx, f.ID) })
	e.expire(t, closed.ID, 300)

	got, err := e.flows.ExpiredPending(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if ids := flowIDs(got); len(ids) != 2 || ids[0] != older.ID || ids[1] != newer.ID {
		t.Fatalf("ExpiredPending = %v, want [%v %v]", ids, older.ID, newer.ID)
	}
	if got[0].AccountID != older.AccountID || got[0].Kind != flow.KindRegistration {
		t.Errorf("flow = %+v", got[0])
	}
	got, err = e.flows.ExpiredPending(t.Context(), 1)
	if err != nil || len(got) != 1 || got[0].ID != older.ID {
		t.Fatalf("ExpiredPending(1) = %v, %v", flowIDs(got), err)
	}
}

func TestLockExpired(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	f := e.openFlow(t, flow.KindRegistration)
	e.expire(t, f.ID, 60)
	found, err := e.flows.ExpiredPending(t.Context(), 1)
	if err != nil || len(found) != 1 {
		t.Fatalf("ExpiredPending = %v, %v", found, err)
	}

	err = e.uow.Do(t.Context(), func(ctx context.Context) error {
		_, err := e.flows.LockExpired(ctx, found[0])
		return err
	})
	if !errors.Is(err, postgres.ErrLockOrder) {
		t.Fatalf("without the account lock: %v, want ErrLockOrder", err)
	}

	e.do(t, func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, f.AccountID); err != nil {
			return err
		}
		lf, err := e.flows.LockExpired(ctx, found[0])
		if err != nil {
			return err
		}
		return e.flows.Cancel(ctx, lf.ID, flow.CloseExpired)
	})
	if cancelled, _, reason, _ := e.flowCols(t, f.ID); !cancelled || reason != "expired" {
		t.Errorf("flow cancelled %v, reason %q", cancelled, reason)
	}
	if open, secrets := e.openSecrets(t, f.ID); open != 0 || secrets != 0 {
		t.Errorf("challenges open %d, with secrets %d; want 0, 0 (I-5)", open, secrets)
	}

	// Closed, and live: both miss.
	live := e.openFlow(t, flow.KindRegistration)
	liveFound, err := e.flows.Find(t.Context(), live.ID, live.HandleHash)
	if err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]flow.Flow{"closed": found[0], "live": liveFound} {
		err := e.uow.Do(t.Context(), func(ctx context.Context) error {
			if _, err := e.repo.GetForUpdate(ctx, target.AccountID); err != nil {
				return err
			}
			_, err := e.flows.LockExpired(ctx, target)
			return err
		})
		var de *domain.Error
		if !errors.As(err, &de) || de.Code != domain.CodeNotFound {
			t.Errorf("%s: %v, want NOT_FOUND", name, err)
		}
	}
}

func TestCloseExpired(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	signIn := e.openFlow(t, flow.KindSignIn)
	e.expire(t, signIn.ID, 60)
	e.exec(t, "UPDATE flows SET pending_secret = '\\x00' WHERE id = ?", signIn.ID)
	pending := e.openFlow(t, flow.KindRegistration)
	e.expire(t, pending.ID, 60)
	invited := e.openFlow(t, flow.KindInvitation)
	e.expire(t, invited.ID, 60)
	activated := e.openFlow(t, flow.KindRegistration)
	e.expire(t, activated.ID, 60)
	e.do(t, func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, activated.AccountID); err != nil {
			return err
		}
		return e.repo.Activate(ctx, activated.AccountID)
	})
	live := e.openFlow(t, flow.KindSignIn)
	before := e.version(t, signIn.AccountID)

	n, err := e.flows.CloseExpired(t.Context(), 10)
	if err != nil || n != 2 {
		t.Fatalf("CloseExpired = %d, %v; want 2 (the sign-in flow, the active account's registration)", n, err)
	}
	if cancelled, _, reason, _ := e.flowCols(t, activated.ID); !cancelled || reason != "expired" {
		t.Errorf("an active account's expired registration: cancelled %v, reason %q", cancelled, reason)
	}
	cancelled, _, reason, secret := e.flowCols(t, signIn.ID)
	if !cancelled || reason != "expired" || secret != nil {
		t.Errorf("sign-in flow: cancelled %v, reason %q, pending secret %x", cancelled, reason, secret)
	}
	if open, secrets := e.openSecrets(t, signIn.ID); open != 0 || secrets != 0 {
		t.Errorf("challenges open %d, with secrets %d; want 0, 0 (I-5)", open, secrets)
	}
	if v := e.version(t, signIn.AccountID); v != before {
		t.Errorf("account version %d, want %d: closing a flow is not an account change", v, before)
	}
	for name, f := range map[string]flow.NewFlow{"pending registration": pending, "pending invitation": invited, "live": live} {
		if cancelled, completed, _, _ := e.flowCols(t, f.ID); cancelled || completed {
			t.Errorf("%s flow closed", name)
		}
	}
}

func TestCloseExpiredSkipsLocked(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	f := e.openFlow(t, flow.KindSignIn)
	e.expire(t, f.ID, 60)

	tx, err := e.su.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), "SELECT 1 FROM flows WHERE id = ? FOR UPDATE", f.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := e.flows.CloseExpired(t.Context(), 10); err != nil || n != 0 {
		t.Fatalf("CloseExpired with the flow locked = %d, %v; want 0", n, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if n, err := e.flows.CloseExpired(t.Context(), 10); err != nil || n != 1 {
		t.Fatalf("CloseExpired after = %d, %v; want 1", n, err)
	}
}

func TestCloseExpiredLimit(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	for range 3 {
		e.expire(t, e.openFlow(t, flow.KindSignIn).ID, 60)
	}
	for _, want := range []int{2, 1, 0} {
		if n, err := e.flows.CloseExpired(t.Context(), 2); err != nil || n != want {
			t.Fatalf("CloseExpired = %d, %v; want %d", n, err, want)
		}
	}
}

func TestCloseExpiredChallenges(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	f := e.openFlow(t, flow.KindRegistration)
	acc := f.AccountID
	idID, value := e.identifierOf(t, acc)
	live := e.otpChallenge(f.ID, idID, value, "654321")
	e.exec(t, "UPDATE challenges SET expires_at = now() - interval '1 second' WHERE flow_id = ?", f.ID)
	e.openChallenges(t, f, live)

	n, err := e.flows.CloseExpiredChallenges(t.Context(), 10)
	if err != nil || n != 1 {
		t.Fatalf("CloseExpiredChallenges = %d, %v; want 1", n, err)
	}
	if open, secrets := e.openSecrets(t, f.ID); open != 1 || secrets != 1 {
		t.Errorf("challenges open %d, with secrets %d; want the live one only (I-5)", open, secrets)
	}
	var closedWithSecret int
	if err := e.su.QueryRowContext(t.Context(),
		"SELECT count(*) FROM challenges WHERE flow_id = ? AND id <> ? AND (closed_at IS NULL OR secret IS NOT NULL)",
		f.ID, live.ID).Scan(&closedWithSecret); err != nil || closedWithSecret != 0 {
		t.Errorf("expired challenge still open or holding its secret: %d, %v", closedWithSecret, err)
	}
	if cancelled, completed, _, _ := e.flowCols(t, f.ID); cancelled || completed {
		t.Error("the flow closed with its challenge")
	}
	if n, err := e.flows.CloseExpiredChallenges(t.Context(), 10); err != nil || n != 0 {
		t.Fatalf("again = %d, %v; want 0", n, err)
	}
}
