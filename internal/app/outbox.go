package app

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// OutboxWriter writes outbox rows in the use case's transaction (TDD-06 §1, I-7): they commit with
// the change they report, or not at all. Both methods run inside UnitOfWork.Do, and the relay is
// told of the rows when the transaction commits (TDD-06 §3.3). Nothing secret or personal goes in
// a row (G-6): an event's data holds no identifier value, display name or secret (T-9), and a
// delivery request names secrets and addresses only by reference.
type OutboxWriter interface {
	// Event writes the event eventType about the account, with data, which is marshalled as JSON,
	// as the CloudEvent's data (api/asyncapi.yaml). The account must be locked by
	// Accounts.GetForUpdate in this transaction: the i-th event of the transaction gets the
	// locked version plus i, and the version moves past the last at commit (TDD-06 §2, I-8).
	Event(ctx context.Context, eventType string, accountID uuid.UUID, data any) error
	// Delivery writes req for the delivery adapter, about the account. It needs no lock and moves
	// no version. An empty req.RequestID, a notice's, becomes the row's id (TDD-06 §5).
	Delivery(ctx context.Context, accountID uuid.UUID, req DeliveryRequest) error
}

// DeliveryRequest is a message for the notification service, as the contract's DeliveryRequest
// (api/openapi.yaml, TDD-06 §5). Secrets and addresses are references (auth1:identifier:<id>,
// auth1:challenge-target:<id>, auth1:secret:<id>, auth1:link:<id>), resolved at send time.
type DeliveryRequest struct {
	// RequestID is <challenge id>:<send number> for a challenge; empty for a notice.
	RequestID string
	// Type is the message type, for example auth.phone_verification_code (TDD-06 §7).
	Type string
	// Channel is email or sms.
	Channel string
	// Locale is the account's locale.
	Locale string
	// Recipient is the reference of the address.
	Recipient string
	// Variables are references or plain non-secret values: strings or integers.
	Variables map[string]any
	// Deadline is the challenge's expiry, after which the message is dropped; nil for a notice.
	Deadline *time.Time
}
