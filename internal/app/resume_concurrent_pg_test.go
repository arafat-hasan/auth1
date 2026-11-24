package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// TestResumeNoDeadlock (G-5): resume steps lock several accounts, by id, then the flows, then
// their challenges, then the address. Run together with each other and with the one-account steps
// of the same accounts (a registration code, a resend), which lock the account, the flow, the
// challenges and the address, nothing deadlocks: every answer is a domain answer, never a store
// failure. And however the tries interleave, no resume challenge takes more than its max_attempts.
func TestResumeNoDeadlock(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	ss, _ := e.resumed(t, 3)
	// Many tries per challenge, so the candidates stay open and locked for the whole run.
	e.exec(t, "UPDATE challenges SET max_attempts = 100000")

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		failures []error
		runs     int
	)
	run := func(step func(ctx context.Context) error) {
		wg.Go(func() {
			for ctx.Err() == nil {
				err := step(context.WithoutCancel(ctx))
				var de *domain.Error
				mu.Lock()
				runs++
				if err != nil && (!errors.As(err, &de) || de.Code == domain.CodeUnavailable) {
					failures = append(failures, err)
				}
				mu.Unlock()
			}
		})
	}
	for range 4 {
		run(func(ctx context.Context) error {
			_, err := e.reg.VerifyResume(ctx, verifyCmd(flow.Secret("000000")))
			return err
		})
	}
	for range 2 {
		run(func(ctx context.Context) error { return e.reg.RequestResume(ctx, resumeCmd()) })
	}
	for _, s := range ss {
		run(func(ctx context.Context) error {
			_, err := e.reg.VerifyCode(ctx, app.VerifyRegistrationCode{FlowID: s.FlowID, Handle: s.Handle,
				IdentifierType: "email", Code: flow.Secret("000000"), IP: resumeIP})
			return err
		})
		run(func(ctx context.Context) error {
			return e.reg.Resend(ctx, app.ResendRegistration{FlowID: s.FlowID, Handle: s.Handle, IdentifierType: "email", IP: resumeIP})
		})
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("%d of %d steps failed in the store, the first: %v", len(failures), runs, failures[0])
	}
	if runs < 50 {
		t.Errorf("only %d steps ran; the test proves little", runs)
	}
	var over int
	if err := e.su.QueryRowContext(t.Context(),
		"SELECT count(*) FROM challenges WHERE attempts > max_attempts").Scan(&over); err != nil || over != 0 {
		t.Errorf("%d challenges past their max_attempts, %v", over, err)
	}
	t.Logf("%d steps", runs)
}

// lockOrder records the accounts and flows a step locks, in order.
type lockOrder struct {
	mu    sync.Mutex
	locks []string // "account <id>" or "flow <id>"
}

func (o *lockOrder) add(kind string, id uuid.UUID) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.locks = append(o.locks, kind+" "+id.String())
}

type orderAccounts struct {
	app.Accounts
	o *lockOrder
}

func (a orderAccounts) GetForUpdate(ctx context.Context, id uuid.UUID) (account.Account, error) {
	a.o.add("account", id)
	return a.Accounts.GetForUpdate(ctx, id)
}

type orderFlows struct {
	app.Flows
	o *lockOrder
}

func (f orderFlows) LockFlow(ctx context.Context, fl flow.Flow) (flow.Flow, error) {
	f.o.add("flow", fl.ID)
	return f.Flows.LockFlow(ctx, fl)
}

// TestResumeLockOrder (G-5): a resume request and a resume verify lock every account first, in
// ascending id order, then the flows, in ascending id order, whatever order the lookups found
// them in (newest first, which is not id order).
func TestResumeLockOrder(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	e.resumed(t, 3)
	o := &lockOrder{}
	d := e.deps
	d.Accounts, d.Flows = orderAccounts{Accounts: d.Accounts, o: o}, orderFlows{Flows: d.Flows, o: o}
	reg, err := app.NewRegistration(d, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	e.age(t, 2*time.Minute)
	check := func(step string) {
		t.Helper()
		var accounts, flows []string
		for i, l := range o.locks {
			kind, id, _ := strings.Cut(l, " ")
			switch {
			case kind == "account" && len(flows) > 0:
				t.Errorf("%s: account locked after a flow, at %d: %v", step, i, o.locks)
			case kind == "account":
				accounts = append(accounts, id)
			default:
				flows = append(flows, id)
			}
		}
		if len(accounts) != 3 || len(flows) != 3 || !slices.IsSorted(accounts) || !slices.IsSorted(flows) {
			t.Errorf("%s locked %v; want 3 accounts, then 3 flows, each in ascending id order", step, o.locks)
		}
		o.locks = nil
	}
	if err := reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	check("RequestResume")
	_, err = reg.VerifyResume(t.Context(), verifyCmd(flow.Secret("000000")))
	checkCodeInvalid(t, "wrong code", err)
	check("VerifyResume")
}
