package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// ClientAssertions implements app.ClientAssertions on client_assertions (TDD-05 §2).
type ClientAssertions struct {
	db *bun.DB
}

// NewClientAssertions returns the repository on db.
func NewClientAssertions(db *bun.DB) *ClientAssertions {
	return &ClientAssertions{db: db}
}

// Record implements app.ClientAssertions with one INSERT … ON CONFLICT DO NOTHING; a conflict
// waits for a concurrent uncommitted insert of the same pair, so one of them alone is new.
func (r *ClientAssertions) Record(ctx context.Context, clientID, jti string, expiresAt time.Time) (bool, error) {
	res, err := Conn(ctx, r.db).ExecContext(ctx, `
		INSERT INTO client_assertions (client_id, jti, expires_at) VALUES (?, ?, ?)
		ON CONFLICT DO NOTHING`, clientID, jti, expiresAt)
	if err != nil {
		return false, fmt.Errorf("record client assertion: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("record client assertion: %w", err)
	}
	return n == 1, nil
}
