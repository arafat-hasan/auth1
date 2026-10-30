package app

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// ErrResolverUnavailable is returned by a DeliveryResolver that cannot answer now; the delivery
// is retried.
var ErrResolverUnavailable = errors.New("delivery resolver unavailable")

// DeliveryRow is a delivery outbox row as the relay hands it to the adapter (TDD-06 §3.2).
type DeliveryRow struct {
	// ID is the outbox row's id.
	ID uuid.UUID
	// AccountID is the row's subject; zero when it has none.
	AccountID uuid.UUID
	// Request is the row's body. Its RequestID is always set: a notice's is the row's id.
	Request DeliveryRequest
}

// DeliveryResult is what the relay does with a row after MessageDelivery.Send (TDD-06 §3.2).
type DeliveryResult int

// The results. The zero value is none of them: an adapter that returns DeliveryOutcome{} has
// forgotten to say what happened, and the relay parks the row rather than publish it.
const (
	_ DeliveryResult = iota
	// DeliverySent: the message was handed over (2xx, or a duplicate). The row is published.
	DeliverySent
	// DeliveryDropped: a reference is closed, so the message must not be sent. The row is
	// published without sending.
	DeliveryDropped
	// DeliveryRetry: a transient failure. The row is retried with backoff.
	DeliveryRetry
	// DeliveryParked: the request is wrong and retrying will not help. The row is parked and an
	// alert raised.
	DeliveryParked
)

// DeliveryOutcome is the result of one send. Reason says why it was not sent, for the row's
// last_error; it holds nothing secret or personal (G-6).
type DeliveryOutcome struct {
	Result DeliveryResult
	Reason string
}

// MessageDelivery hands a delivery request to its channel (SDD D-16, TDD-06 §8, §9). The relay
// owns retries, so adapters are stateless: Send tries once and says what happened. It is called
// outside any transaction (G-4).
type MessageDelivery interface {
	Send(ctx context.Context, row DeliveryRow) DeliveryOutcome
}

// DeliveryResolver resolves the references of a delivery request that auth1 sent, under the
// resolver rules of TDD-06 §6: only references that appear in the row named requestID, and only
// while they are open. A reference absent from the answer is closed, and the message must not be
// sent. Resolving reads only (I-15). The values are never stored, logged or emitted.
type DeliveryResolver interface {
	Resolve(ctx context.Context, requestID string, refs []string) (map[string]string, error)
}
