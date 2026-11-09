package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// FlowExpiryJob is the flow-expiry job's name: its metric label, log field, and the id of the
// system actor of its events and audit entries (TDD-08 §7).
const FlowExpiryJob = "flow-expiry"

// DefaultExpiryBatch is how many rows one expiry query takes (TDD-02 §2.5).
const DefaultExpiryBatch = 500

// auditRegistrationExpire is the audit action of an expired registration or invitation.
const auditRegistrationExpire = "registration.expire"

// FlowExpiryDeps are the ports the expiry job uses. Every field but Logger is required.
type FlowExpiryDeps struct {
	UnitOfWork UnitOfWork
	Accounts   Accounts
	Flows      Flows
	Expiring   ExpiringFlows
	Outbox     OutboxWriter
	Audit      AuditWriter
	Logger     *slog.Logger // for an account the run could not expire; nil logs nothing
}

// missing returns the names of the required fields of d that are nil, in field order.
func (d FlowExpiryDeps) missing() []string {
	fields := []struct {
		name string
		nil  bool
	}{
		{"UnitOfWork", d.UnitOfWork == nil}, {"Accounts", d.Accounts == nil}, {"Flows", d.Flows == nil},
		{"Expiring", d.Expiring == nil}, {"Outbox", d.Outbox == nil}, {"Audit", d.Audit == nil},
	}
	var out []string
	for _, f := range fields {
		if f.nil {
			out = append(out, f.name)
		}
	}
	return out
}

// FlowExpiry is the flow-expiry job (TDD-02 §2.5). It runs on the leader, every minute.
type FlowExpiry struct {
	d     FlowExpiryDeps
	batch int
}

// NewFlowExpiry returns the job, taking batch rows per query (DefaultExpiryBatch when batch is
// not above 0), or an error naming the missing dependencies.
func NewFlowExpiry(d FlowExpiryDeps, batch int) (*FlowExpiry, error) {
	if m := d.missing(); len(m) > 0 {
		return nil, fmt.Errorf("flow expiry: missing %s", strings.Join(m, ", "))
	}
	if batch <= 0 {
		batch = DefaultExpiryBatch
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	return &FlowExpiry{d: d, batch: batch}, nil
}

// Run expires what has expired, in batches, until none is left: first each pending account whose
// registration or invitation expired, one transaction each; then the other expired flows; then
// the expired challenges of open flows. An account that fails is logged and left for the next
// run, and the others go on; Run then returns an error, so the run does not count as a success.
func (e *FlowExpiry) Run(ctx context.Context) error {
	errs := []error{e.expirePending(ctx)}
	if ctx.Err() == nil {
		errs = append(errs, drain(ctx, e.batch, e.d.Expiring.CloseExpired))
	}
	if ctx.Err() == nil {
		errs = append(errs, drain(ctx, e.batch, e.d.Expiring.CloseExpiredChallenges))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("flow expiry: %w", err)
	}
	return ctx.Err()
}

// expirePending expires the pending accounts of expired registrations and invitations. A flow it
// leaves (failed, or skipped under the lock) is not taken again in this run, so the run ends. A
// failure of one flow is logged and the others go on; a failure of the store (UNAVAILABLE, or ctx
// ended) ends the pass at once. It returns the first failure, with how many flows failed.
func (e *FlowExpiry) expirePending(ctx context.Context) error {
	left := map[uuid.UUID]bool{}
	var first error
	failed := 0
	result := func() error {
		switch failed {
		case 0:
			return nil
		case 1:
			return first
		}
		return fmt.Errorf("%d flows not expired; the first: %w", failed, first)
	}
	for ctx.Err() == nil {
		limit := e.batch + len(left)
		fs, err := e.d.Expiring.ExpiredPending(ctx, limit)
		if err != nil {
			return errors.Join(result(), err)
		}
		tried := 0
		for _, f := range fs {
			if left[f.ID] || ctx.Err() != nil {
				continue
			}
			tried++
			expired, err := e.expire(ctx, f)
			if err != nil {
				failed++
				if first == nil {
					first = err
				}
				if outage(err) {
					return result()
				}
				e.d.Logger.LogAttrs(ctx, slog.LevelError, "flow expiry failed", slog.String("job", FlowExpiryJob),
					slog.String("flow_id", f.ID.String()), slog.String("account_id", f.AccountID.String()),
					slog.String("error", err.Error()))
			}
			if !expired {
				left[f.ID] = true
			}
		}
		if len(fs) < limit || tried == 0 {
			break
		}
	}
	return result()
}

// outage reports whether err is a failure of the store or of the run rather than of one flow: the
// next flows would fail the same way.
func outage(err error) bool {
	var de *domain.Error
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &de) && de.Code == domain.CodeUnavailable)
}

// errSkip rolls back a transaction that found nothing to expire under its locks.
var errSkip = errors.New("flow expiry: nothing to expire")

// expire expires one flow and its pending account in one transaction, locking the account, then
// the flow (G-5). It reports false, changing nothing, when the account is no longer pending or the
// flow no longer open and expired.
func (e *FlowExpiry) expire(ctx context.Context, f flow.Flow) (bool, error) {
	err := e.d.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		acc, err := e.d.Accounts.GetForUpdate(ctx, f.AccountID)
		if err != nil {
			return err
		}
		d, ok := account.Expire(acc.Status)
		if !ok {
			return errSkip
		}
		lf, err := e.d.Expiring.LockExpired(ctx, f)
		var de *domain.Error
		if errors.As(err, &de) && de.Code == domain.CodeNotFound {
			return errSkip
		}
		if err != nil {
			return err
		}
		if err := e.d.Flows.Cancel(ctx, lf.ID, flow.CloseExpired); err != nil {
			return err
		}
		if err := e.d.Accounts.ApplyStatus(ctx, acc.ID, d); err != nil {
			return err
		}
		actor := SystemActor(FlowExpiryJob)
		if err := e.d.Outbox.Event(ctx, EventRegistrationExpired, acc.ID, RegistrationExpired{
			AccountID: acc.ID, ClientID: acc.RegisteredVia, Actor: actor,
		}); err != nil {
			return err
		}
		entry := AuditEntry{AccountID: acc.ID, ActorKind: ActorSystem, ActorID: actor.ID,
			Action: auditRegistrationExpire, Outcome: OutcomeSuccess}
		entry.withFlow(lf)
		return e.d.Audit.Write(ctx, entry)
	})
	if err == errSkip { //nolint:errorlint // exactly the sentinel: a rollback failure joined to it is a failure
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("expire flow %s: %w", f.ID, err)
	}
	return true, nil
}

// drain calls closeBatch until it closes fewer than batch rows.
func drain(ctx context.Context, batch int, closeBatch func(context.Context, int) (int, error)) error {
	for ctx.Err() == nil {
		n, err := closeBatch(ctx, batch)
		if err != nil {
			return err
		}
		if n < batch {
			return nil
		}
	}
	return nil
}
