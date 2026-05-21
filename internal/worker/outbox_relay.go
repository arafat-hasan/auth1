package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/duitara/services/auth-service/internal/app/repo"
)

const (
	exchangeName = "duitara.events"
	exchangeType = "topic"
)

// OutboxRelayConfig holds tuning parameters for the relay worker.
type OutboxRelayConfig struct {
	PollInterval time.Duration
	MaxAttempts  int
	BatchSize    int
}

// OutboxRelay polls the email_outbox table and publishes pending rows to RabbitMQ.
type OutboxRelay struct {
	outboxRepo OutboxRepoTx
	amqpURL    string
	cfg        OutboxRelayConfig
	logger     *logrus.Logger
}

// OutboxRepoTx is the subset of OutboxRepository used by the relay.
type OutboxRepoTx interface {
	repo.OutboxRepository
}

func NewOutboxRelay(
	outboxRepo OutboxRepoTx,
	amqpURL string,
	cfg OutboxRelayConfig,
	logger *logrus.Logger,
) *OutboxRelay {
	return &OutboxRelay{
		outboxRepo: outboxRepo,
		amqpURL:    amqpURL,
		cfg:        cfg,
		logger:     logger,
	}
}

// Run starts the relay loop. It blocks until ctx is cancelled.
func (r *OutboxRelay) Run(ctx context.Context) {
	r.logger.Info("outbox relay started")

	conn, ch, err := r.connect()
	if err != nil {
		r.logger.WithError(err).Error("outbox relay: initial connection failed, will retry on next tick")
	}

	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("outbox relay stopping")
			if ch != nil {
				ch.Close()
			}
			if conn != nil {
				conn.Close()
			}
			return

		case <-ticker.C:
			if conn == nil || conn.IsClosed() {
				conn, ch, err = r.connect()
				if err != nil {
					r.logger.WithError(err).Error("outbox relay: reconnect failed")
					continue
				}
			}
			r.processBatch(ctx, ch)
		}
	}
}

func (r *OutboxRelay) connect() (*amqp.Connection, *amqp.Channel, error) {
	conn, err := amqp.Dial(r.amqpURL)
	if err != nil {
		return nil, nil, fmt.Errorf("amqp dial: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("amqp channel: %w", err)
	}

	// Declare the topic exchange (idempotent — safe to call on every reconnect).
	if err = ch.ExchangeDeclare(
		exchangeName,
		exchangeType,
		true,  // durable
		false, // auto-delete
		false, // internal
		false, // no-wait
		nil,
	); err != nil {
		ch.Close()
		conn.Close()
		return nil, nil, fmt.Errorf("exchange declare: %w", err)
	}

	// Enable publisher confirms so we know the broker received the message.
	if err = ch.Confirm(false); err != nil {
		ch.Close()
		conn.Close()
		return nil, nil, fmt.Errorf("enable publisher confirms: %w", err)
	}

	r.logger.Info("outbox relay: connected to RabbitMQ")
	return conn, ch, nil
}

func (r *OutboxRelay) processBatch(ctx context.Context, ch *amqp.Channel) {
	rows, err := r.outboxRepo.GetPending(ctx, r.cfg.BatchSize)
	if err != nil {
		r.logger.WithError(err).Error("outbox relay: failed to fetch pending rows")
		return
	}

	for _, row := range rows {
		log := r.logger.WithFields(logrus.Fields{
			"outbox_id":  row.ID,
			"event_type": row.EventType,
		})

		// Increment attempt counter before publishing.
		if err = r.outboxRepo.IncrementAttempts(ctx, row.ID); err != nil {
			log.WithError(err).Error("outbox relay: failed to increment attempts")
			continue
		}

		if row.Attempts+1 >= r.cfg.MaxAttempts {
			errMsg := "max attempts reached"
			if row.LastError != nil {
				errMsg = fmt.Sprintf("max attempts reached; last error: %s", *row.LastError)
			}
			_ = r.outboxRepo.MarkFailed(ctx, row.ID, errMsg)
			log.WithField("attempts", row.Attempts+1).Warn("outbox relay: row marked as failed after max attempts")
			continue
		}

		// Extract routing key from the stored payload.
		routingKey, body, err := r.marshalPayload(row.Payload)
		if err != nil {
			errMsg := err.Error()
			_ = r.outboxRepo.MarkFailed(ctx, row.ID, errMsg)
			log.WithError(err).Error("outbox relay: failed to marshal payload")
			continue
		}

		confirms := ch.NotifyPublish(make(chan amqp.Confirmation, 1))

		pubErr := ch.PublishWithContext(ctx,
			exchangeName,
			routingKey,
			true,  // mandatory
			false, // immediate
			amqp.Publishing{
				ContentType:  "application/json",
				DeliveryMode: amqp.Persistent,
				Body:         body,
				MessageId:    row.ID.String(),
				Timestamp:    row.CreatedAt,
			},
		)
		if pubErr != nil {
			errMsg := pubErr.Error()
			_ = r.outboxRepo.MarkFailed(ctx, row.ID, errMsg)
			log.WithError(pubErr).Error("outbox relay: publish failed")
			continue
		}

		// Wait for broker confirm.
		select {
		case confirm := <-confirms:
			if !confirm.Ack {
				errMsg := "broker nacked the message"
				_ = r.outboxRepo.MarkFailed(ctx, row.ID, errMsg)
				log.Error("outbox relay: " + errMsg)
				continue
			}
		case <-time.After(5 * time.Second):
			errMsg := "timed out waiting for broker confirm"
			_ = r.outboxRepo.MarkFailed(ctx, row.ID, errMsg)
			log.Error("outbox relay: " + errMsg)
			continue
		case <-ctx.Done():
			return
		}

		if err = r.outboxRepo.MarkPublished(ctx, row.ID); err != nil {
			log.WithError(err).Error("outbox relay: failed to mark row as published")
		} else {
			log.WithField("routing_key", routingKey).Info("outbox relay: event published")
		}
	}
}

// marshalPayload extracts the routing_key and returns the full payload as JSON bytes.
func (r *OutboxRelay) marshalPayload(payload map[string]interface{}) (routingKey string, body []byte, err error) {
	rk, ok := payload["routing_key"].(string)
	if !ok || rk == "" {
		return "", nil, fmt.Errorf("missing or invalid routing_key in payload")
	}

	body, err = json.Marshal(payload)
	if err != nil {
		return "", nil, fmt.Errorf("json marshal payload: %w", err)
	}

	return rk, body, nil
}
