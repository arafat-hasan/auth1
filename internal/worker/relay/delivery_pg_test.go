package relay_test

import (
	"context"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
	"github.com/arafat-hasan/auth1/internal/worker/relay"
)

// pgEnv is a migrated database with the superuser's pool and a writer as auth1_app.
type pgEnv struct {
	appDSN string
	su     *bun.DB
	uow    *postgres.UnitOfWork
	outbox *postgres.Outbox
}

// open opens a pool on dsn, closed when the test ends.
func open(t *testing.T, dsn string) *bun.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(path, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := postgres.Open(config.Database{DSNFile: config.NewSecretFile(path), MaxConns: 10}, config.EnvDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newPGEnv(t *testing.T) *pgEnv {
	t.Helper()
	dsn := pgtest.DSN(t)
	appDSN := pgtest.As(t, dsn, pgtest.App)
	appDB := open(t, appDSN)
	return &pgEnv{
		appDSN: appDSN, su: open(t, dsn),
		uow:    postgres.NewUnitOfWork(appDB, 5*time.Second, noop.NewTracerProvider()),
		outbox: postgres.NewOutbox(appDB, system.UUIDv7{}),
	}
}

// relayOn returns a relay's view of the outbox on a pool of its own, as another replica has.
func (e *pgEnv) relayOn(t *testing.T) *postgres.DeliveryOutbox {
	t.Helper()
	db := open(t, e.appDSN)
	return postgres.NewDeliveryOutbox(db, postgres.NewUnitOfWork(db, 5*time.Second, noop.NewTracerProvider()))
}

// write writes the requests in one transaction.
func (e *pgEnv) write(t *testing.T, reqs ...app.DeliveryRequest) {
	t.Helper()
	if err := e.uow.Do(t.Context(), func(ctx context.Context) error {
		for _, r := range reqs {
			if err := e.outbox.Delivery(ctx, uuid.Nil, r); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// notice is a notice request; its request_id becomes its row id.
func notice() app.DeliveryRequest {
	return app.DeliveryRequest{
		Type: "auth.notice_password_changed", Channel: "email", Locale: "en",
		Recipient: app.IdentifierRef(uuid.New()), Variables: map[string]any{"how": "reset"},
	}
}

// waitPending waits until no delivery row is pending (neither published nor parked).
func (e *pgEnv) waitPending(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		var n int
		if err := e.su.QueryRowContext(t.Context(),
			"SELECT count(*) FROM outbox WHERE published_at IS NULL AND parked_at IS NULL").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d rows still pending after %v", n, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// counter is a delivery adapter that counts sends per request id.
type counter struct {
	mu    sync.Mutex
	sends map[string]int
}

func (c *counter) Send(_ context.Context, row app.DeliveryRow) app.DeliveryOutcome {
	time.Sleep(time.Duration(rand.IntN(5)) * time.Millisecond) //nolint:gosec // test timing
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sends[row.Request.RequestID]++
	return app.DeliveryOutcome{Result: app.DeliverySent}
}

// TestTwoRelaysSendOnce checks the issue's first done-when item: with two relay instances, each
// on its own pool, every row is sent exactly once in the happy path. It fails without the lease.
func TestTwoRelaysSendOnce(t *testing.T) {
	t.Parallel()
	e := newPGEnv(t)
	const rows = 300
	reqs := make([]app.DeliveryRequest, rows)
	for i := range reqs {
		reqs[i] = notice()
	}
	e.write(t, reqs...)

	c := &counter{sends: map[string]int{}}
	for range 2 {
		opt := options(e.relayOn(t), c)
		opt.PollInterval, opt.BatchSize = 10*time.Millisecond, 10
		start(t, opt)
	}
	e.waitPending(t, 60*time.Second)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sends) != rows {
		t.Errorf("%d distinct requests sent, want %d", len(c.sends), rows)
	}
	for id, n := range c.sends {
		if n != 1 {
			t.Errorf("request %s sent %d times", id, n)
		}
	}
	var published int
	if err := e.su.QueryRowContext(t.Context(),
		"SELECT count(*) FROM outbox WHERE published_at IS NOT NULL AND last_error IS NULL AND attempts = 1").Scan(&published); err != nil {
		t.Fatal(err)
	}
	if published != rows {
		t.Errorf("%d rows published on the first attempt, want %d", published, rows)
	}
}

// TestClosedChallengeNotSent checks the issue's second done-when item: a message whose challenge
// has closed (here, purged) is dropped unsent.
func TestClosedChallengeNotSent(t *testing.T) {
	t.Parallel()
	e := newPGEnv(t)
	gone := uuid.New()
	deadline := time.Now().Add(time.Minute)
	e.write(t, app.DeliveryRequest{
		RequestID: gone.String() + ":1", Type: "auth.sign_in_code", Channel: "sms", Locale: "en",
		Recipient: app.IdentifierRef(uuid.New()), Variables: map[string]any{"code": app.SecretRef(gone)},
		Deadline: &deadline,
	})
	c := &counter{sends: map[string]int{}}
	opt := options(e.relayOn(t), c)
	opt.PollInterval = 10 * time.Millisecond
	start(t, opt)
	e.waitPending(t, 10*time.Second)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sends) != 0 {
		t.Errorf("sent %v, want nothing", c.sends)
	}
	var lastError string
	if err := e.su.QueryRowContext(t.Context(),
		"SELECT last_error FROM outbox WHERE published_at IS NOT NULL").Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if lastError != "dropped: challenge closed" {
		t.Errorf("last_error = %q, want dropped: challenge closed", lastError)
	}
}

// TestRetryThenPark checks the issue's third done-when item against the database: a transient
// failure (a 5xx) is retried after the backoff, and parked once max_attempts is spent; a request
// error (a 4xx) is parked at once.
func TestRetryThenPark(t *testing.T) {
	t.Parallel()
	e := newPGEnv(t)
	transient, wrong := notice(), notice()
	e.write(t, transient)
	var transientID uuid.UUID
	if err := e.su.QueryRowContext(t.Context(), "SELECT id FROM outbox").Scan(&transientID); err != nil {
		t.Fatal(err)
	}
	e.write(t, wrong)

	var mu sync.Mutex
	var sendTimes []time.Time
	opt := options(e.relayOn(t), fakeDelivery{fn: func(_ context.Context, row app.DeliveryRow) app.DeliveryOutcome {
		if row.ID != transientID {
			return app.DeliveryOutcome{Result: app.DeliveryParked, Reason: "notification service answered 400"}
		}
		mu.Lock()
		sendTimes = append(sendTimes, time.Now())
		mu.Unlock()
		return app.DeliveryOutcome{Result: app.DeliveryRetry, Reason: "notification service answered 503"}
	}})
	opt.PollInterval, opt.MaxAttempts = 10*time.Millisecond, 2
	opt.Jitter = func() float64 { return 0 }
	start(t, opt)
	e.waitPending(t, 15*time.Second)

	mu.Lock()
	if len(sendTimes) != 2 {
		t.Fatalf("transient row sent %d times, want 2", len(sendTimes))
	}
	if gap := sendTimes[1].Sub(sendTimes[0]); gap < relay.Backoff(1, 0)-50*time.Millisecond {
		t.Errorf("retried after %v, want at least the 1s backoff", gap)
	}
	mu.Unlock()
	rows, err := e.su.QueryContext(t.Context(), "SELECT id, attempts, last_error FROM outbox WHERE parked_at IS NOT NULL ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	got := map[uuid.UUID]string{}
	for rows.Next() {
		var id uuid.UUID
		var attempts int
		var lastError string
		if err := rows.Scan(&id, &attempts, &lastError); err != nil {
			t.Fatal(err)
		}
		got[id] = lastError
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[transientID] != "parked: attempts exhausted: notification service answered 503" {
		t.Errorf("parked rows = %v, want both, the transient one after its attempts", got)
	}
}
