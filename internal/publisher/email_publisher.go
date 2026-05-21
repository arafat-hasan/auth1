package publisher

import "context"

// Routing keys used when publishing to the duitara.events topic exchange.
const (
	RoutingKeyEmailOTP           = "email.otp"
	RoutingKeyEmailPasswordReset = "email.password_reset"
)

// EmailEvent is the payload written to the outbox and later published to RabbitMQ.
type EmailEvent struct {
	// IdempotencyKey deduplicates repeated enqueue calls, e.g. "otp:user@example.com:signup".
	// Leave empty when deduplication is not required (e.g. password reset).
	IdempotencyKey string

	// RoutingKey determines which consumers receive this event, e.g. "email.otp".
	RoutingKey string

	// EventType is a human-readable label stored in the outbox for observability.
	EventType string

	To        string
	Subject   string
	Template  string
	Variables map[string]string
}

// EmailPublisher enqueues an email event into the transactional outbox.
// The outbox relay worker later picks it up and publishes it to RabbitMQ.
type EmailPublisher interface {
	Enqueue(ctx context.Context, event *EmailEvent) error
}
