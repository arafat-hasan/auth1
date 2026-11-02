package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// TestDeliveryStatsUseIndexes checks that the backlog queries, which every replica runs every 15 s,
// read a partial index rather than the whole outbox, where published rows stay for 7 days. With
// sequential scans priced out, a plan that still scans outbox has no index to use.
func TestDeliveryStatsUseIndexes(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("pgx", pgtest.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(t.Context(), "SET enable_seqscan = off"); err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]string{"age": statsAgeQuery, "parked": statsParkedQuery} {
		plan := explain(t.Context(), t, conn, query)
		if strings.Contains(plan, "Seq Scan on outbox") {
			t.Errorf("%s query scans the outbox:\n%s", name, plan)
		}
	}
}

// explain returns query's plan as text.
func explain(ctx context.Context, t *testing.T, conn *sql.Conn, query string) string {
	t.Helper()
	rows, err := conn.QueryContext(ctx, "EXPLAIN "+query)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		b.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
