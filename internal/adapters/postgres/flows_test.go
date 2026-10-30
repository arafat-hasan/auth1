package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// flowsEnv is the flows repository beside the accounts one, on one database.
type flowsEnv struct {
	*accountsEnv
	flows *postgres.Flows
	n     int // the last account number flowAccount used
}

// flowsDB returns a fresh environment.
func flowsDB(t *testing.T) *flowsEnv {
	t.Helper()
	return flowsDBWith(t, nil)
}

// flowsDBWith is flowsDB with wrap applied to the field encryption the flows repository uses.
func flowsDBWith(t *testing.T, wrap func(app.FieldCrypto) app.FieldCrypto) *flowsEnv {
	t.Helper()
	e := accountsDB(t)
	fc := e.fc
	if wrap != nil {
		fc = wrap(fc)
	}
	return &flowsEnv{accountsEnv: e, flows: postgres.NewFlows(e.app, fc, e.bidx)}
}

// flowAccount creates a pending account with an email of its own and returns its id.
func (e *flowsEnv) flowAccount(t *testing.T) uuid.UUID {
	t.Helper()
	e.n++
	a := e.newAccount("", fmt.Sprintf("person%d@example.org", e.n))
	e.create(t, a)
	return a.ID
}

// handle returns a distinct handle hash for name.
func handle(name string) []byte { return crypto.SHA256([]byte("handle:" + name)) }

// newFlow is an open flow of kind for the account, expiring in an hour.
func (e *flowsEnv) newFlow(accountID uuid.UUID, kind flow.Kind, handleHash []byte) flow.NewFlow {
	states := map[flow.Kind]flow.State{
		flow.KindRegistration:    flow.RegistrationState{PendingTypes: []string{"email"}},
		flow.KindSignIn:          flow.SignInState{FirstFactor: flow.FirstFactorPassword, Step: flow.StepSecondFactor},
		flow.KindTOTPReplacement: flow.TOTPReplacementState{},
		flow.KindPhoneChange:     flow.PhoneChangeState{},
	}
	return flow.NewFlow{
		ID: e.ids.New(), Kind: kind, AccountID: accountID, ClientID: "web", HandleHash: handleHash,
		State: states[kind], ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
	}
}

// open opens f in its own transaction, under the account lock.
func (e *flowsEnv) open(t *testing.T, f flow.NewFlow) {
	t.Helper()
	e.do(t, func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, f.AccountID); err != nil {
			return err
		}
		return e.flows.Open(ctx, f)
	})
}

// locked runs fn in one transaction after locking f's account and f, found by its handle.
func (e *flowsEnv) locked(t *testing.T, f flow.NewFlow, fn func(ctx context.Context, f flow.Flow) error) {
	t.Helper()
	found, err := e.flows.Find(t.Context(), f.ID, f.HandleHash)
	if err != nil {
		t.Fatal(err)
	}
	e.do(t, func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, found.AccountID); err != nil {
			return err
		}
		lf, err := e.flows.LockFlow(ctx, found)
		if err != nil {
			return err
		}
		return fn(ctx, lf)
	})
}

// flowCols reads raw columns of the flow as superuser.
func (e *flowsEnv) flowCols(t *testing.T, id uuid.UUID) (cancelled, completed bool, reason string, pending []byte) {
	t.Helper()
	err := e.su.QueryRowContext(t.Context(), `
		SELECT cancelled_at IS NOT NULL, completed_at IS NOT NULL, coalesce(close_reason, ''), pending_secret
		FROM flows WHERE id = ?`, id).Scan(&cancelled, &completed, &reason, &pending)
	if err != nil {
		t.Fatal(err)
	}
	return cancelled, completed, reason, pending
}

// flowTimes ignores the times the database sets.
var flowTimes = cmpopts.IgnoreFields(flow.Flow{}, "CreatedAt")

func TestOpenAndFind(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	nf := e.newFlow(acc, flow.KindTOTPReplacement, handle("a"))
	nf.PendingSecret = flow.Secret("JBSWY3DPEHPK3PXP")
	e.open(t, nf)

	want := flow.Flow{
		ID: nf.ID, Kind: nf.Kind, AccountID: acc, ClientID: "web", HandleHash: nf.HandleHash,
		State: flow.TOTPReplacementState{}, ExpiresAt: nf.ExpiresAt,
	}
	got, err := e.flows.Find(t.Context(), nf.ID, nf.HandleHash)
	if err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff(want, got, flowTimes); d != "" {
		t.Errorf("Find (-want +got):\n%s", d)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	byHandle, err := e.flows.FindByHandle(t.Context(), nf.HandleHash)
	if err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff(want, byHandle, flowTimes); d != "" {
		t.Errorf("FindByHandle (-want +got):\n%s", d)
	}

	// Only a lock decrypts the pending secret.
	e.locked(t, nf, func(_ context.Context, f flow.Flow) error {
		if string(f.PendingSecret) != "JBSWY3DPEHPK3PXP" {
			t.Errorf("LockFlow PendingSecret = %q", []byte(f.PendingSecret))
		}
		return nil
	})
}

// TestFindIndistinguishable checks I-20: without the right handle, or once the flow has expired
// or closed, every finder answers the same CHALLENGE_CLOSED.
func TestFindIndistinguishable(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	live := e.newFlow(acc, flow.KindSignIn, handle("live"))
	e.open(t, live)
	expired := e.newFlow(acc, flow.KindSignIn, handle("expired"))
	e.open(t, expired)
	e.exec(t, "UPDATE flows SET expires_at = now() - interval '1 second' WHERE id = ?", expired.ID)
	closed := e.newFlow(acc, flow.KindSignIn, handle("closed"))
	e.open(t, closed)
	e.locked(t, closed, func(ctx context.Context, f flow.Flow) error { return e.flows.Complete(ctx, f.ID) })

	misses := map[string]func() error{
		"unknown id":       func() error { _, err := e.flows.Find(t.Context(), e.ids.New(), live.HandleHash); return err },
		"wrong handle":     func() error { _, err := e.flows.Find(t.Context(), live.ID, handle("other")); return err },
		"no handle":        func() error { _, err := e.flows.Find(t.Context(), live.ID, nil); return err },
		"expired":          func() error { _, err := e.flows.Find(t.Context(), expired.ID, expired.HandleHash); return err },
		"closed":           func() error { _, err := e.flows.Find(t.Context(), closed.ID, closed.HandleHash); return err },
		"handle unknown":   func() error { _, err := e.flows.FindByHandle(t.Context(), handle("other")); return err },
		"handle nil":       func() error { _, err := e.flows.FindByHandle(t.Context(), nil); return err },
		"handle expired":   func() error { _, err := e.flows.FindByHandle(t.Context(), expired.HandleHash); return err },
		"handle closed":    func() error { _, err := e.flows.FindByHandle(t.Context(), closed.HandleHash); return err },
		"another's handle": func() error { _, err := e.flows.Find(t.Context(), expired.ID, live.HandleHash); return err },
	}
	want := &domain.Error{Code: domain.CodeChallengeClosed, Detail: "the challenge is closed"}
	for name, miss := range misses {
		err := miss()
		var de *domain.Error
		if !errors.As(err, &de) {
			t.Errorf("%s: error = %v, want a *domain.Error", name, err)
			continue
		}
		if d := cmp.Diff(want, de); d != "" {
			t.Errorf("%s: error (-want +got):\n%s", name, d)
		}
		if err.Error() != want.Error() {
			t.Errorf("%s: text %q, want %q", name, err.Error(), want.Error())
		}
	}
	if _, err := e.flows.Find(t.Context(), live.ID, live.HandleHash); err != nil {
		t.Errorf("the live flow: %v", err)
	}
}

func TestOpenReplaces(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	first := e.newFlow(acc, flow.KindRegistration, handle("first"))
	e.open(t, first)
	otherKind := e.newFlow(acc, flow.KindPhoneChange, handle("phone"))
	e.open(t, otherKind)
	other := e.flowAccount(t)
	otherAccount := e.newFlow(other, flow.KindRegistration, handle("other account"))
	e.open(t, otherAccount)

	second := e.newFlow(acc, flow.KindRegistration, handle("second"))
	e.open(t, second)

	cancelled, completed, reason, _ := e.flowCols(t, first.ID)
	if !cancelled || completed || reason != string(flow.CloseReplaced) {
		t.Errorf("replaced flow: cancelled %v, completed %v, reason %q", cancelled, completed, reason)
	}
	checkCode(t, func() error { _, err := e.flows.Find(t.Context(), first.ID, first.HandleHash); return err }(),
		domain.CodeChallengeClosed)
	for _, f := range []flow.NewFlow{second, otherKind, otherAccount} {
		if _, err := e.flows.Find(t.Context(), f.ID, f.HandleHash); err != nil {
			t.Errorf("flow %s: %v", f.Kind, err)
		}
	}

	// An open flow past expires_at, which the expiry job has not closed yet, closes as expired.
	e.exec(t, "UPDATE flows SET expires_at = now() - interval '1 minute' WHERE id = ?", otherKind.ID)
	e.open(t, e.newFlow(acc, flow.KindPhoneChange, handle("phone again")))
	if cancelled, _, reason, _ := e.flowCols(t, otherKind.ID); !cancelled || reason != string(flow.CloseExpired) {
		t.Errorf("expired flow replaced: cancelled %v, reason %q; want expired", cancelled, reason)
	}
}

func TestSignInFlowsCoexist(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	a, b := e.newFlow(acc, flow.KindSignIn, handle("a")), e.newFlow(acc, flow.KindSignIn, handle("b"))
	e.open(t, a)
	e.open(t, b)
	for _, f := range []flow.NewFlow{a, b} {
		if _, err := e.flows.Find(t.Context(), f.ID, f.HandleHash); err != nil {
			t.Errorf("flow %v: %v", f.ID, err)
		}
	}
}

func TestUpdateFlow(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	nf := e.newFlow(e.flowAccount(t), flow.KindRegistration, handle("a"))
	e.open(t, nf)
	state := flow.RegistrationState{PendingTypes: []string{}}
	e.locked(t, nf, func(ctx context.Context, f flow.Flow) error { return e.flows.Update(ctx, f.ID, state, 2) })
	got, err := e.flows.Find(t.Context(), nf.ID, nf.HandleHash)
	if err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff(flow.State(state), got.State); d != "" || got.Attempts != 2 {
		t.Errorf("state (-want +got):\n%s; attempts %d, want 2", d, got.Attempts)
	}

	for _, wrong := range []flow.State{nil, flow.SignInState{}} {
		err := e.uow.Do(t.Context(), func(ctx context.Context) error {
			if _, err := e.repo.GetForUpdate(ctx, got.AccountID); err != nil {
				return err
			}
			if _, err := e.flows.LockFlow(ctx, got); err != nil {
				return err
			}
			return e.flows.Update(ctx, got.ID, wrong, 0)
		})
		if !errors.Is(err, flow.ErrStateInvalid) {
			t.Errorf("Update with state %T: %v, want ErrStateInvalid", wrong, err)
		}
	}
}

// TestReplaceHandle checks that a replaced handle finds nothing, even for a lock taken on a flow
// found under the old handle before the replacement.
func TestReplaceHandle(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	nf := e.newFlow(e.flowAccount(t), flow.KindRegistration, handle("old"))
	e.open(t, nf)
	stale, err := e.flows.Find(t.Context(), nf.ID, nf.HandleHash)
	if err != nil {
		t.Fatal(err)
	}
	e.locked(t, nf, func(ctx context.Context, f flow.Flow) error {
		return e.flows.ReplaceHandle(ctx, f.ID, handle("new"))
	})
	checkCode(t, func() error { _, err := e.flows.Find(t.Context(), nf.ID, handle("old")); return err }(),
		domain.CodeChallengeClosed)
	if _, err := e.flows.Find(t.Context(), nf.ID, handle("new")); err != nil {
		t.Errorf("new handle: %v", err)
	}
	err = e.uow.Do(t.Context(), func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, stale.AccountID); err != nil {
			return err
		}
		_, err := e.flows.LockFlow(ctx, stale)
		return err
	})
	checkCode(t, err, domain.CodeChallengeClosed)
}

func TestCompleteAndCancel(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	done := e.newFlow(acc, flow.KindSignIn, handle("done"))
	e.open(t, done)
	gone := e.newFlow(acc, flow.KindSignIn, handle("gone"))
	e.open(t, gone)
	e.locked(t, done, func(ctx context.Context, f flow.Flow) error { return e.flows.Complete(ctx, f.ID) })
	e.locked(t, gone, func(ctx context.Context, f flow.Flow) error {
		return e.flows.Cancel(ctx, f.ID, flow.CloseAttempts)
	})
	if cancelled, completed, reason, _ := e.flowCols(t, done.ID); cancelled || !completed || reason != "" {
		t.Errorf("completed flow: cancelled %v, completed %v, reason %q", cancelled, completed, reason)
	}
	if cancelled, completed, reason, _ := e.flowCols(t, gone.ID); !cancelled || completed || reason != "attempts" {
		t.Errorf("cancelled flow: cancelled %v, completed %v, reason %q", cancelled, completed, reason)
	}
}

// TestFlowLockOrder checks that the methods that need a lock refuse to run without it, or
// outside a transaction, before they query (G-5).
func TestFlowLockOrder(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	nf := e.newFlow(acc, flow.KindRegistration, handle("a"))
	e.open(t, nf)
	found, err := e.flows.Find(t.Context(), nf.ID, nf.HandleHash)
	if err != nil {
		t.Fatal(err)
	}
	state := flow.RegistrationState{}
	calls := map[string]func(ctx context.Context) error{
		"LockFlow": func(ctx context.Context) error { _, err := e.flows.LockFlow(ctx, found); return err },
		"Open": func(ctx context.Context) error {
			return e.flows.Open(ctx, e.newFlow(acc, flow.KindSignIn, handle("b")))
		},
		"Update":        func(ctx context.Context) error { return e.flows.Update(ctx, nf.ID, state, 0) },
		"ReplaceHandle": func(ctx context.Context) error { return e.flows.ReplaceHandle(ctx, nf.ID, handle("c")) },
		"Complete":      func(ctx context.Context) error { return e.flows.Complete(ctx, nf.ID) },
		"Cancel":        func(ctx context.Context) error { return e.flows.Cancel(ctx, nf.ID, flow.CloseExpired) },
	}
	for name, call := range calls {
		if err := call(t.Context()); !errors.Is(err, postgres.ErrNoTransaction) {
			t.Errorf("%s outside a transaction: %v, want ErrNoTransaction", name, err)
		}
		err := e.uow.Do(t.Context(), call)
		if !errors.Is(err, postgres.ErrLockOrder) {
			t.Errorf("%s without its lock: %v, want ErrLockOrder", name, err)
		}
	}
	// With only the account locked, the flow methods still refuse.
	for _, name := range []string{"Update", "ReplaceHandle", "Complete", "Cancel"} {
		err := e.uow.Do(t.Context(), func(ctx context.Context) error {
			if _, err := e.repo.GetForUpdate(ctx, acc); err != nil {
				return err
			}
			return calls[name](ctx)
		})
		if !errors.Is(err, postgres.ErrLockOrder) {
			t.Errorf("%s with the account locked only: %v, want ErrLockOrder", name, err)
		}
	}
	// Nothing changed.
	if _, err := e.flows.Find(t.Context(), nf.ID, nf.HandleHash); err != nil {
		t.Errorf("the flow: %v", err)
	}
}

// TestLockFlowOtherAccount checks that LockFlow re-checks the account: a flow presented with
// another account locked finds nothing.
func TestLockFlowOtherAccount(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc, other := e.flowAccount(t), e.flowAccount(t)
	nf := e.newFlow(acc, flow.KindRegistration, handle("a"))
	e.open(t, nf)
	found, err := e.flows.Find(t.Context(), nf.ID, nf.HandleHash)
	if err != nil {
		t.Fatal(err)
	}
	forged := found
	forged.AccountID = other
	err = e.uow.Do(t.Context(), func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, other); err != nil {
			return err
		}
		_, err := e.flows.LockFlow(ctx, forged)
		return err
	})
	checkCode(t, err, domain.CodeChallengeClosed)
}
