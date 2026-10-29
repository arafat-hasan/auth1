package system_test

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // the pgx database/sql driver

	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

func TestClockNow(t *testing.T) {
	t.Parallel()
	before := time.Now()
	got := system.Clock{}.Now()
	after := time.Now()

	if got.Location() != time.UTC {
		t.Errorf("location = %v, want UTC", got.Location())
	}
	if ns := got.Nanosecond() % 1000; ns != 0 {
		t.Errorf("%v has %d ns below a microsecond, want 0", got, ns)
	}
	if got.Before(before.Truncate(time.Microsecond)) || got.After(after) {
		t.Errorf("Now() = %v, want between %v and %v", got, before, after)
	}
}

// A time from the clock goes into a timestamptz and comes back equal.
func TestClockRoundTripsThroughPostgres(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("pgx", pgtest.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	now := system.Clock{}.Now()
	var got time.Time
	if err := db.QueryRowContext(t.Context(), "SELECT $1::timestamptz", now).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(now) {
		t.Errorf("read back %v, want %v", got, now)
	}
}
