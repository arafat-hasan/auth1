package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/app"
)

// Audit implements app.AuditWriter on auth_audit (TDD-01 §4). The row's at is the database's
// now(): the transaction's start inside UnitOfWork.Do, the statement's outside.
type Audit struct {
	db *bun.DB
}

// NewAudit returns the writer on db.
func NewAudit(db *bun.DB) *Audit {
	return &Audit{db: db}
}

// Write implements app.AuditWriter.
func (w *Audit) Write(ctx context.Context, e app.AuditEntry) error {
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	body, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("write audit entry: details: %w", err)
	}
	var ip any
	if e.IP.IsValid() {
		ip = e.IP.String()
	}
	if _, err := Conn(ctx, w.db).ExecContext(ctx, `
		INSERT INTO auth_audit (account_id, actor_kind, actor_id, on_behalf, action, outcome, client_id, ip, user_agent, details)
		VALUES (?, ?, nullif(?, ''), nullif(?, ''), ?, ?, nullif(?, ''), ?::inet, nullif(?, ''), ?::jsonb)`,
		uuid.NullUUID{UUID: e.AccountID, Valid: e.AccountID != uuid.Nil}, e.ActorKind, e.ActorID, e.OnBehalf,
		e.Action, e.Outcome, e.ClientID, ip, e.UserAgent, string(body)); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return nil
}
