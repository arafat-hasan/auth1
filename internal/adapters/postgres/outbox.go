package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/propagation"

	"github.com/arafat-hasan/auth1/internal/app"
)

// ErrAccountNotLocked is returned, without querying, by Outbox.Event for an account that
// Accounts.GetForUpdate has not locked in the transaction: its version could not be assigned
// from the locked row (TDD-06 §2).
var ErrAccountNotLocked = errors.New("postgres: account not locked in the transaction")

// outboxChannel is the channel the writing transaction notifies, with the destination as
// payload, and the relay listens on (TDD-06 §3.3).
const outboxChannel = "auth1_outbox"

// Outbox implements app.OutboxWriter on the outbox table (TDD-06 §1, §2).
type Outbox struct {
	db  *bun.DB
	ids app.IDGenerator
}

// NewOutbox returns the writer on db, with row ids from ids.
func NewOutbox(db *bun.DB, ids app.IDGenerator) *Outbox {
	return &Outbox{db: db, ids: ids}
}

// Event implements app.OutboxWriter.
func (o *Outbox) Event(ctx context.Context, eventType string, accountID uuid.UUID, data any) error {
	t := txFrom(ctx)
	if t == nil {
		return fmt.Errorf("write event: %w", ErrNoTransaction)
	}
	a := t.account(accountID)
	if a == nil {
		return fmt.Errorf("write event: %w", ErrAccountNotLocked)
	}
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("write event: data: %w", err)
	}
	carrier := traceCarrier(ctx)
	if err := o.insert(ctx, "event", accountID, a.version+a.events+1, o.ids.New(), eventType, body, carrier); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	a.events++
	return nil
}

// deliveryBody is a delivery row's body: the contract's DeliveryRequest (TDD-06 §5).
type deliveryBody struct {
	RequestID   string         `json:"request_id"`
	Type        string         `json:"type"`
	Channel     string         `json:"channel"`
	Locale      string         `json:"locale"`
	Recipient   string         `json:"recipient"`
	Variables   map[string]any `json:"variables"`
	Deadline    *time.Time     `json:"deadline,omitempty"`
	Traceparent string         `json:"traceparent,omitempty"`
}

// Delivery implements app.OutboxWriter.
func (o *Outbox) Delivery(ctx context.Context, accountID uuid.UUID, req app.DeliveryRequest) error {
	if !inTx(ctx) {
		return fmt.Errorf("write delivery: %w", ErrNoTransaction)
	}
	id := o.ids.New()
	carrier := traceCarrier(ctx)
	b := deliveryBody{
		RequestID: req.RequestID, Type: req.Type, Channel: req.Channel, Locale: req.Locale,
		Recipient: req.Recipient, Variables: req.Variables, Traceparent: carrier["traceparent"],
	}
	if b.RequestID == "" {
		b.RequestID = id.String()
	}
	if b.Variables == nil {
		b.Variables = map[string]any{}
	}
	if req.Deadline != nil {
		d := req.Deadline.UTC()
		b.Deadline = &d
	}
	body, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("write delivery: %w", err)
	}
	if err := o.insert(ctx, "delivery", accountID, 0, id, req.Type, body, carrier); err != nil {
		return fmt.Errorf("write delivery: %w", err)
	}
	return nil
}

// insert stores a pending row, due now, and notifies the relay of its destination at commit. A
// zero version, a delivery's, is stored as null.
func (o *Outbox) insert(ctx context.Context, destination string, subject uuid.UUID, version int64,
	id uuid.UUID, rowType string, body []byte, carrier propagation.MapCarrier,
) error {
	var traceContext any
	if len(carrier) > 0 {
		tc, err := json.Marshal(carrier)
		if err != nil {
			return fmt.Errorf("trace context: %w", err)
		}
		traceContext = string(tc)
	}
	_, err := Conn(ctx, o.db).ExecContext(ctx, `
		WITH row AS (
			INSERT INTO outbox (id, destination, subject, account_version, type, body, trace_context, created_at, next_attempt_at)
			VALUES (?, ?, ?, nullif(?, 0), ?, ?::jsonb, ?::jsonb, now(), now())
			RETURNING destination
		)
		SELECT pg_notify(?, destination) FROM row`,
		id, destination, uuid.NullUUID{UUID: subject, Valid: subject != uuid.Nil}, version, rowType,
		string(body), traceContext, outboxChannel)
	return err
}

// traceCarrier returns ctx's W3C trace context (traceparent and tracestate) for the relay to
// continue the trace; empty when ctx has no valid span.
func traceCarrier(ctx context.Context) propagation.MapCarrier {
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, carrier)
	return carrier
}
