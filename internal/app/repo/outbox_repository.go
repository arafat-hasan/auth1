package repo

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/app/model/db"
)

type OutboxRepository interface {
	GetPending(ctx context.Context, limit int) ([]*db.EmailOutbox, error)
	MarkPublished(ctx context.Context, id uuid.UUID) error
	MarkFailed(ctx context.Context, id uuid.UUID, errMsg string) error
	IncrementAttempts(ctx context.Context, id uuid.UUID) error
	CountByStatus(ctx context.Context, status string) (int, error)
}

type outboxRepository struct {
	db *bun.DB
}

func NewOutboxRepository(db *bun.DB) OutboxRepository {
	return &outboxRepository{db: db}
}

func (r *outboxRepository) GetPending(ctx context.Context, limit int) ([]*db.EmailOutbox, error) {
	var rows []*db.EmailOutbox
	err := r.db.NewSelect().
		Model(&rows).
		Where("status = 'pending'").
		OrderExpr("created_at ASC").
		Limit(limit).
		For("UPDATE SKIP LOCKED").
		Scan(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get pending outbox rows: %w", err)
	}
	return rows, nil
}

func (r *outboxRepository) MarkPublished(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	_, err := r.db.NewUpdate().
		Model((*db.EmailOutbox)(nil)).
		Set("status = 'published', published_at = ?", now).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to mark outbox row as published: %w", err)
	}
	return nil
}

func (r *outboxRepository) MarkFailed(ctx context.Context, id uuid.UUID, errMsg string) error {
	_, err := r.db.NewUpdate().
		Model((*db.EmailOutbox)(nil)).
		Set("status = 'failed', last_error = ?", errMsg).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to mark outbox row as failed: %w", err)
	}
	return nil
}

func (r *outboxRepository) IncrementAttempts(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.NewUpdate().
		Model((*db.EmailOutbox)(nil)).
		Set("attempts = attempts + 1").
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to increment outbox attempts: %w", err)
	}
	return nil
}

func (r *outboxRepository) CountByStatus(ctx context.Context, status string) (int, error) {
	count, err := r.db.NewSelect().
		Model((*db.EmailOutbox)(nil)).
		Where("status = ?", status).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count outbox rows by status: %w", err)
	}
	return count, nil
}
