package publisher

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/model/db"
)

// outboxPayload is the JSON structure stored in email_outbox.payload.
type outboxPayload struct {
	RoutingKey string            `json:"routing_key"`
	To         string            `json:"to"`
	Subject    string            `json:"subject"`
	Template   string            `json:"template"`
	Variables  map[string]string `json:"variables"`
}

// OutboxWriter implements EmailPublisher by writing to the email_outbox table.
type OutboxWriter struct {
	db *bun.DB
}

func NewOutboxWriter(db *bun.DB) *OutboxWriter {
	return &OutboxWriter{db: db}
}

func (w *OutboxWriter) Enqueue(ctx context.Context, event *EmailEvent) error {
	payload := outboxPayload{
		RoutingKey: event.RoutingKey,
		To:         event.To,
		Subject:    event.Subject,
		Template:   event.Template,
		Variables:  event.Variables,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal email event payload: %w", err)
	}

	var jsonMap map[string]interface{}
	if err = json.Unmarshal(raw, &jsonMap); err != nil {
		return fmt.Errorf("failed to prepare payload map: %w", err)
	}

	row := &db.EmailOutbox{
		EventType: event.EventType,
		Payload:   db.Metadata(jsonMap),
		Status:    "pending",
	}

	if event.IdempotencyKey != "" {
		row.IdempotencyKey = &event.IdempotencyKey
	}

	_, err = w.db.NewInsert().
		Model(row).
		On("CONFLICT (idempotency_key) DO NOTHING").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to enqueue email event: %w", err)
	}

	return nil
}
