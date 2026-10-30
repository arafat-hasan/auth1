package postgres_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
)

var _ app.AuditWriter = (*postgres.Audit)(nil)

// auditRow is an auth_audit row without id and at, nullable columns as their text.
type auditRow struct {
	AccountID               uuid.NullUUID
	ActorKind               string
	ActorID, OnBehalf       sql.NullString
	Action, Outcome         string
	ClientID, IP, UserAgent sql.NullString
	Details                 map[string]any
	AtIsNow                 bool
}

// auditRows returns every auth_audit row, ordered by id.
func auditRows(t *testing.T, e *accountsEnv) []auditRow {
	t.Helper()
	rs, err := e.su.QueryContext(t.Context(), `
		SELECT account_id, actor_kind, actor_id, on_behalf, action, outcome, client_id, host(ip), user_agent,
		       details::text, at BETWEEN now() - interval '1 minute' AND now()
		FROM auth_audit ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rs.Close() }()
	var out []auditRow
	for rs.Next() {
		var (
			r       auditRow
			details string
		)
		if err := rs.Scan(&r.AccountID, &r.ActorKind, &r.ActorID, &r.OnBehalf, &r.Action, &r.Outcome,
			&r.ClientID, &r.IP, &r.UserAgent, &details, &r.AtIsNow); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(details), &r.Details); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func str(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }

func TestAuditWrite(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	audit := postgres.NewAudit(e.app)
	id := e.ids.New()

	full := app.AuditEntry{
		AccountID: id, ActorKind: "service", ActorID: "spiffe://example.org/support", OnBehalf: "agent 42",
		Action: "account.suspend", Outcome: "success", ClientID: "support-console",
		IP: netip.MustParseAddr("2001:db8::1"), UserAgent: "curl/8.0",
		Details: map[string]any{"reason_code": "abuse", "sessions_revoked": 2},
	}
	bare := app.AuditEntry{ActorKind: "anonymous", Action: "sign_in", Outcome: "failure"}
	for _, entry := range []app.AuditEntry{full, bare} {
		if err := audit.Write(t.Context(), entry); err != nil {
			t.Fatalf("Write(%s): %v", entry.Action, err)
		}
	}

	want := []auditRow{
		{
			AccountID: uuid.NullUUID{UUID: id, Valid: true}, ActorKind: "service",
			ActorID: str("spiffe://example.org/support"), OnBehalf: str("agent 42"),
			Action: "account.suspend", Outcome: "success", ClientID: str("support-console"),
			IP: str("2001:db8::1"), UserAgent: str("curl/8.0"),
			Details: map[string]any{"reason_code": "abuse", "sessions_revoked": float64(2)}, AtIsNow: true,
		},
		{ActorKind: "anonymous", Action: "sign_in", Outcome: "failure", Details: map[string]any{}, AtIsNow: true},
	}
	if diff := cmp.Diff(want, auditRows(t, e)); diff != "" {
		t.Errorf("audit rows (-want +got):\n%s", diff)
	}
}

// TestAuditInUnitOfWork checks that an entry written inside a use case commits or rolls back with
// it, and that one written after the rollback, outside the transaction, stays.
func TestAuditInUnitOfWork(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	audit := postgres.NewAudit(e.app)

	e.do(t, func(ctx context.Context) error {
		return audit.Write(ctx, app.AuditEntry{ActorKind: "system", Action: "committed", Outcome: "success"})
	})
	failed := errors.New("use case failed")
	err := e.uow.Do(t.Context(), func(ctx context.Context) error {
		if err := audit.Write(ctx, app.AuditEntry{ActorKind: "system", Action: "rolled_back", Outcome: "success"}); err != nil {
			return err
		}
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatalf("Do = %v, want the use case's error", err)
	}
	if err := audit.Write(t.Context(), app.AuditEntry{ActorKind: "system", Action: "after_rollback", Outcome: "failure"}); err != nil {
		t.Fatal(err)
	}

	var actions []string
	for _, r := range auditRows(t, e) {
		actions = append(actions, r.Action)
	}
	if diff := cmp.Diff([]string{"committed", "after_rollback"}, actions); diff != "" {
		t.Errorf("audited actions (-want +got):\n%s", diff)
	}
}

func TestAuditRefusesBadDetails(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	audit := postgres.NewAudit(e.app)
	err := audit.Write(t.Context(), app.AuditEntry{
		ActorKind: "system", Action: "x", Outcome: "success", Details: map[string]any{"bad": make(chan int)},
	})
	if err == nil {
		t.Error("Write with details that are not JSON succeeded")
	}
}
