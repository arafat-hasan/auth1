package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// ErrLockOrder is returned, without querying, by a method whose prerequisite lock the transaction
// has not taken: the account before its flow, the flow before its challenges (G-5, TDD-01 §4.2).
var ErrLockOrder = errors.New("postgres: lock order: a prerequisite lock is not held")

// The places of the flow aggregate's encrypted columns (TDD-01 §3.1).
const (
	tableFlows      = "flows"
	tableChallenges = "challenges"
)

// Flows implements app.Flows on flows and challenges (TDD-01 §4, TDD-02 §2).
type Flows struct {
	db   *bun.DB
	fc   app.FieldCrypto
	bidx app.BlindIndex
}

// NewFlows returns the repository on db, encrypting through fc and indexing targets with bidx.
func NewFlows(db *bun.DB, fc app.FieldCrypto, bidx app.BlindIndex) *Flows {
	return &Flows{db: db, fc: fc, bidx: bidx}
}

// flowClosed is every finder's miss, the same for an unknown id, a wrong or missing handle and
// an expired or closed flow (I-20): a new value each time, with the text verification gives.
func flowClosed() error {
	return &domain.Error{Code: domain.CodeChallengeClosed, Detail: "the challenge is closed"}
}

// flowColumns are the columns scanFlow reads, in its order.
const flowColumns = `f.id, f.kind, f.account_id, f.client_id, f.handle_hash, f.state, f.attempts, f.expires_at,
	f.completed_at, f.cancelled_at, coalesce(f.close_reason, ''), f.created_at`

// flowOpen is the condition of an open flow, and flowLive of one a finder sees (TDD-02 §2.1).
const (
	flowOpen = "f.completed_at IS NULL AND f.cancelled_at IS NULL"
	flowLive = flowOpen + " AND f.expires_at > now()"
)

// scanFlow reads a row of flowColumns, followed by extra.
func scanFlow(row interface{ Scan(...any) error }, extra ...any) (flow.Flow, error) {
	var (
		f                    flow.Flow
		kind, reason         string
		state                []byte
		completed, cancelled sql.NullTime
	)
	err := row.Scan(append([]any{&f.ID, &kind, &f.AccountID, &f.ClientID, &f.HandleHash, &state, &f.Attempts,
		&f.ExpiresAt, &completed, &cancelled, &reason, &f.CreatedAt}, extra...)...)
	if err != nil {
		return flow.Flow{}, err
	}
	if f.Kind, err = flow.ParseKind(kind); err != nil {
		return flow.Flow{}, err
	}
	if f.State, err = flow.UnmarshalState(f.Kind, state); err != nil {
		return flow.Flow{}, err
	}
	f.CloseReason = flow.CloseReason(reason)
	f.CompletedAt, f.CancelledAt = timePtr(completed), timePtr(cancelled)
	f.ExpiresAt, f.CreatedAt = f.ExpiresAt.UTC(), f.CreatedAt.UTC()
	return f, nil
}

// find reads the live flow matching where.
func (r *Flows) find(ctx context.Context, op, where string, args ...any) (flow.Flow, error) {
	f, err := scanFlow(Conn(ctx, r.db).QueryRowContext(ctx,
		"SELECT "+flowColumns+" FROM flows f WHERE "+where+" AND "+flowLive, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return flow.Flow{}, flowClosed()
	}
	if err != nil {
		return flow.Flow{}, fmt.Errorf("%s: %w", op, err)
	}
	return f, nil
}

// Find implements app.Flows.
func (r *Flows) Find(ctx context.Context, id uuid.UUID, handleHash []byte) (flow.Flow, error) {
	return r.find(ctx, "find flow", "f.id = ? AND f.handle_hash = ?", id, handleHash)
}

// FindByHandle implements app.Flows.
func (r *Flows) FindByHandle(ctx context.Context, handleHash []byte) (flow.Flow, error) {
	return r.find(ctx, "find flow", "f.handle_hash = ?", handleHash)
}

// LockFlow implements app.Flows.
func (r *Flows) LockFlow(ctx context.Context, f flow.Flow) (flow.Flow, error) {
	t := txFrom(ctx)
	if t == nil {
		return flow.Flow{}, fmt.Errorf("lock flow: %w", ErrNoTransaction)
	}
	if t.account(f.AccountID) == nil {
		return flow.Flow{}, fmt.Errorf("lock flow: %w", ErrLockOrder)
	}
	var pending []byte
	got, err := scanFlow(t.tx.QueryRowContext(ctx, "SELECT "+flowColumns+", f.pending_secret FROM flows f "+
		"WHERE f.id = ? AND f.account_id = ? AND f.handle_hash = ? AND "+flowLive+" FOR UPDATE",
		f.ID, f.AccountID, f.HandleHash), &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return flow.Flow{}, flowClosed()
	}
	if err != nil {
		return flow.Flow{}, fmt.Errorf("lock flow: %w", err)
	}
	t.lockFlow(got.ID)
	if pending != nil {
		plain, err := r.fc.Open(app.NewPlace(tableFlows, "pending_secret", got.ID), pending)
		if err != nil {
			return flow.Flow{}, fmt.Errorf("lock flow: pending secret: %w", err)
		}
		got.PendingSecret = plain
	}
	return got, nil
}

// Open implements app.Flows.
func (r *Flows) Open(ctx context.Context, f flow.NewFlow) error {
	t := txFrom(ctx)
	if t == nil {
		return fmt.Errorf("open flow: %w", ErrNoTransaction)
	}
	if t.account(f.AccountID) == nil {
		return fmt.Errorf("open flow: %w", ErrLockOrder)
	}
	if f.State == nil || f.State.Kind() != f.Kind {
		return fmt.Errorf("open flow: %w: state is not of kind %s", flow.ErrStateInvalid, f.Kind)
	}
	state, err := flow.MarshalState(f.State)
	if err != nil {
		return fmt.Errorf("open flow: %w", err)
	}
	var pending []byte
	if f.PendingSecret != nil {
		if pending, err = r.fc.Seal(app.NewPlace(tableFlows, "pending_secret", f.ID), f.PendingSecret); err != nil {
			return fmt.Errorf("open flow: %w", err)
		}
	}
	if f.Kind != flow.KindSignIn {
		// Flow rows before challenge rows, in one statement (G-5).
		if _, err := t.tx.ExecContext(ctx, `
			WITH f AS (
				UPDATE flows SET cancelled_at = now(), close_reason = ?, pending_secret = NULL
				WHERE account_id = ? AND kind = ? AND completed_at IS NULL AND cancelled_at IS NULL
				RETURNING id)
			UPDATE challenges SET closed_at = now(), secret = NULL
			WHERE flow_id IN (SELECT id FROM f) AND closed_at IS NULL`,
			string(flow.CloseReplaced), f.AccountID, string(f.Kind)); err != nil {
			return fmt.Errorf("open flow: replace: %w", err)
		}
	}
	if _, err := t.tx.ExecContext(ctx, `
		INSERT INTO flows (id, kind, account_id, client_id, handle_hash, state, pending_secret, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?::jsonb, ?, ?, now())`,
		f.ID, string(f.Kind), f.AccountID, f.ClientID, f.HandleHash, string(state), pending, f.ExpiresAt); err != nil {
		return fmt.Errorf("open flow: %w", err)
	}
	t.lockFlow(f.ID)
	return nil
}

// lockedFlow returns the transaction, or the error of op when ctx carries none or the flow id is
// not locked in it.
func lockedFlow(ctx context.Context, op string, id uuid.UUID) (*txn, error) {
	t := txFrom(ctx)
	if t == nil {
		return nil, fmt.Errorf("%s: %w", op, ErrNoTransaction)
	}
	if !slices.Contains(t.flows, id) {
		return nil, fmt.Errorf("%s: %w", op, ErrLockOrder)
	}
	return t, nil
}

// Update implements app.Flows.
func (r *Flows) Update(ctx context.Context, id uuid.UUID, state flow.State, attempts int) error {
	t, err := lockedFlow(ctx, "update flow", id)
	if err != nil {
		return err
	}
	data, err := flow.MarshalState(state)
	if err != nil {
		return fmt.Errorf("update flow: %w", err)
	}
	res, err := t.tx.ExecContext(ctx, `
		UPDATE flows SET state = ?::jsonb, attempts = ?
		WHERE id = ? AND kind = ? AND completed_at IS NULL AND cancelled_at IS NULL`,
		string(data), attempts, id, string(state.Kind()))
	if err != nil {
		return fmt.Errorf("update flow: %w", err)
	}
	return oneRow(res, "update flow", "flow")
}

// ReplaceHandle implements app.Flows.
func (r *Flows) ReplaceHandle(ctx context.Context, id uuid.UUID, handleHash []byte) error {
	t, err := lockedFlow(ctx, "replace flow handle", id)
	if err != nil {
		return err
	}
	res, err := t.tx.ExecContext(ctx,
		"UPDATE flows SET handle_hash = ? WHERE id = ? AND completed_at IS NULL AND cancelled_at IS NULL",
		handleHash, id)
	if err != nil {
		return fmt.Errorf("replace flow handle: %w", err)
	}
	return oneRow(res, "replace flow handle", "flow")
}

// Complete implements app.Flows.
func (r *Flows) Complete(ctx context.Context, id uuid.UUID) error {
	return r.close(ctx, "complete flow", id, "completed_at", "")
}

// Cancel implements app.Flows.
func (r *Flows) Cancel(ctx context.Context, id uuid.UUID, reason flow.CloseReason) error {
	if _, err := flow.ParseCloseReason(string(reason)); err != nil {
		return fmt.Errorf("cancel flow: %w", err)
	}
	return r.close(ctx, "cancel flow", id, "cancelled_at", reason)
}

// close sets column (completed_at or cancelled_at) of the open flow with reason, erasing its
// pending secret, and closes its open challenges, erasing their secrets: one statement, flow row
// before challenge rows (I-5, G-5).
func (r *Flows) close(ctx context.Context, op string, id uuid.UUID, column string, reason flow.CloseReason) error {
	t, err := lockedFlow(ctx, op, id)
	if err != nil {
		return err
	}
	var n int
	err = t.tx.QueryRowContext(ctx, `
		WITH f AS (
			UPDATE flows SET `+column+` = now(), close_reason = nullif(?, ''), pending_secret = NULL
			WHERE id = ? AND completed_at IS NULL AND cancelled_at IS NULL
			RETURNING id),
		c AS (
			UPDATE challenges SET closed_at = now(), secret = NULL
			WHERE flow_id IN (SELECT id FROM f) AND closed_at IS NULL)
		SELECT count(*) FROM f`, string(reason), id).Scan(&n)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if n == 0 {
		return notFound("flow")
	}
	return nil
}
