package app

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrClaimLost is returned by a DeliveryOutbox outcome write when the row is no longer leased to
// the caller: its lease ran out and another relay claimed it, or it was finished.
var ErrClaimLost = errors.New("delivery claim lost")

// ClaimedDelivery is a delivery row leased to one relay (TDD-06 §3.2).
type ClaimedDelivery struct {
	Row DeliveryRow
	// Attempt is the row's attempts after the claim. It fences the outcome write: a relay whose
	// lease ran out, and whose row was claimed again, writes nothing.
	Attempt int
}

// DeliveryClaim is what one DeliveryOutbox.Claim did.
type DeliveryClaim struct {
	// Rows are the rows leased to the caller.
	Rows []ClaimedDelivery
	// Locked counts the rows the claim locked: leased, dropped and parked. Fewer than asked means
	// no other row is due; as many means more may be.
	Locked int
	// Invalid are the rows parked because their body is not a delivery request.
	Invalid []uuid.UUID
}

// OutboxStats is the delivery backlog the relay reports (TDD-08 §5.2).
type OutboxStats struct {
	// OldestAge is the age of the oldest row neither published nor parked; zero when none.
	OldestAge time.Duration
	// Parked is the number of parked rows.
	Parked int
}

// DeliveryOutbox is the delivery relay's view of the outbox (TDD-06 §3.2). Each method is one
// short transaction of its own; none is open while the relay sends (G-4).
type DeliveryOutbox interface {
	// Claim locks up to n due rows and leases them for lease: their attempts grow by one and they
	// are not due again until the lease ends. Before leasing, it marks published, unsent, the rows
	// that can no longer work (a challenge not open, a notice older than 24 h), and parks rows
	// whose body is not a delivery request.
	Claim(ctx context.Context, n int, lease time.Duration) (DeliveryClaim, error)
	// Publish marks the row published, with lastError (empty when it was sent; the reason when
	// it was dropped).
	Publish(ctx context.Context, c ClaimedDelivery, lastError string) error
	// Retry makes the row due after delay, but no later than its request's deadline, with
	// reason as its last error.
	Retry(ctx context.Context, c ClaimedDelivery, delay time.Duration, reason string) error
	// Park parks the row with reason as its last error.
	Park(ctx context.Context, c ClaimedDelivery, reason string) error
	// Stats reads the delivery backlog.
	Stats(ctx context.Context) (OutboxStats, error)
}
