package postgres_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/trace"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
)

var _ app.OutboxWriter = (*postgres.Outbox)(nil)

// outboxEnv is accountsEnv with the outbox writer.
type outboxEnv struct {
	*accountsEnv
	outbox *postgres.Outbox
}

func outboxDB(t *testing.T) *outboxEnv {
	t.Helper()
	e := accountsDB(t)
	return &outboxEnv{accountsEnv: e, outbox: postgres.NewOutbox(e.app, e.ids)}
}

// account creates a pending account and returns its id.
func (e *outboxEnv) account(t *testing.T) uuid.UUID {
	t.Helper()
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	return na.ID
}

// version reads the account's stored version.
func (e *outboxEnv) version(t *testing.T, id uuid.UUID) int64 {
	t.Helper()
	var v int64
	if err := e.su.QueryRowContext(t.Context(), "SELECT version FROM accounts WHERE id = ?", id).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// outboxRow is the part of an outbox row the writer sets.
type outboxRow struct {
	ID             uuid.UUID
	Destination    string
	Subject        uuid.NullUUID
	AccountVersion sql.NullInt64
	Type           string
	Body           string
	TraceContext   sql.NullString
	Attempts       int
	Pending        bool // next_attempt_at = created_at; published_at, parked_at and last_error null
}

// rows returns every outbox row, ordered by id.
func (e *outboxEnv) rows(t *testing.T) []outboxRow {
	t.Helper()
	rs, err := e.su.QueryContext(t.Context(), `
		SELECT id, destination, subject, account_version, type, body::text, trace_context::text, attempts,
		       next_attempt_at = created_at AND published_at IS NULL AND parked_at IS NULL AND last_error IS NULL
		FROM outbox ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rs.Close() }()
	var out []outboxRow
	for rs.Next() {
		var r outboxRow
		if err := rs.Scan(&r.ID, &r.Destination, &r.Subject, &r.AccountVersion, &r.Type, &r.Body,
			&r.TraceContext, &r.Attempts, &r.Pending); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// eventVersions returns the account_version of each event row, ordered by it.
func (e *outboxEnv) eventVersions(t *testing.T) []int64 {
	t.Helper()
	var vs []int64
	for _, r := range e.rows(t) {
		if r.Destination == "event" {
			vs = append(vs, r.AccountVersion.Int64)
		}
	}
	return vs
}

// lock locks the account in the use case's transaction.
func (e *outboxEnv) lock(ctx context.Context, id uuid.UUID) error {
	_, err := e.repo.GetForUpdate(ctx, id)
	return err
}

// TestEventVersions checks TDD-06 §2: two events in one transaction get consecutive versions
// after the locked row's, and the account ends at the higher one.
func TestEventVersions(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)
	e.exec(t, "UPDATE accounts SET version = 7 WHERE id = ?", id)

	e.do(t, func(ctx context.Context) error {
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		if err := e.outbox.Event(ctx, "account.profile_updated", id, map[string]any{"changed": []string{"locale"}}); err != nil {
			return err
		}
		return e.outbox.Event(ctx, "account.password_changed", id, map[string]any{"account_id": id})
	})

	if diff := cmp.Diff([]int64{8, 9}, e.eventVersions(t)); diff != "" {
		t.Errorf("event versions (-want +got):\n%s", diff)
	}
	if v := e.version(t, id); v != 9 {
		t.Errorf("version = %d, want 9", v)
	}
}

// TestChangeWithoutEventMovesVersion checks TDD-06 §2: a change with no event still increases the
// version, by one, and only when it commits.
func TestChangeWithoutEventMovesVersion(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)

	e.do(t, func(ctx context.Context) error { return e.lock(ctx, id) })
	if v := e.version(t, id); v != 2 {
		t.Errorf("version after a change = %d, want 2", v)
	}

	err := e.uow.Do(t.Context(), func(ctx context.Context) error {
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		return errors.New("use case failed")
	})
	if err == nil {
		t.Fatal("failing use case committed")
	}
	if v := e.version(t, id); v != 2 {
		t.Errorf("version after a rolled-back change = %d, want 2", v)
	}
	if rows := e.rows(t); len(rows) != 0 {
		t.Errorf("outbox rows = %v, want none", rows)
	}
}

// TestLockedTwice checks that locking one account twice in a transaction still moves its version
// once, from the version first read.
func TestLockedTwice(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)
	e.do(t, func(ctx context.Context) error {
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		if err := e.outbox.Event(ctx, "account.mfa_enrolled", id, map[string]any{"via": "self_service"}); err != nil {
			return err
		}
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		return e.outbox.Event(ctx, "account.mfa_removed", id, map[string]any{})
	})
	if diff := cmp.Diff([]int64{2, 3}, e.eventVersions(t)); diff != "" {
		t.Errorf("event versions (-want +got):\n%s", diff)
	}
	if v := e.version(t, id); v != 3 {
		t.Errorf("version = %d, want 3", v)
	}
}

// TestFailedUseCaseLeavesNoOutboxRow checks I-7: the rows a use case writes commit with it or not
// at all, and so does the version.
func TestFailedUseCaseLeavesNoOutboxRow(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)
	failed := errors.New("use case failed")

	err := e.uow.Do(t.Context(), func(ctx context.Context) error {
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		if err := e.outbox.Event(ctx, "account.password_changed", id, map[string]any{}); err != nil {
			return err
		}
		if err := e.outbox.Delivery(ctx, id, noticeRequest()); err != nil {
			return err
		}
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatalf("Do = %v, want the use case's error", err)
	}
	if rows := e.rows(t); len(rows) != 0 {
		t.Errorf("outbox rows after a failed use case = %v, want none", rows)
	}
	if v := e.version(t, id); v != 1 {
		t.Errorf("version = %d, want 1", v)
	}
}

// TestEventRow checks the stored event: body is data, the other columns are the pending event's.
func TestEventRow(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)
	data := map[string]any{"account_id": id, "actor": map[string]any{"kind": "account", "id": id}, "via": "sign_in"}
	e.do(t, func(ctx context.Context) error {
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		return e.outbox.Event(ctx, "account.mfa_enrolled", id, data)
	})

	rows := e.rows(t)
	if len(rows) != 1 {
		t.Fatalf("outbox rows = %v, want one", rows)
	}
	got := rows[0]
	want := outboxRow{
		ID: got.ID, Destination: "event", Subject: uuid.NullUUID{UUID: id, Valid: true},
		AccountVersion: sql.NullInt64{Int64: 2, Valid: true}, Type: "account.mfa_enrolled",
		Body: got.Body, Pending: true,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("row (-want +got):\n%s", diff)
	}
	if got.ID.Version() != 7 {
		t.Errorf("id %v is not a UUIDv7", got.ID)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(got.Body), &body); err != nil {
		t.Fatal(err)
	}
	wantBody := map[string]any{"account_id": id.String(), "actor": map[string]any{"kind": "account", "id": id.String()}, "via": "sign_in"}
	if diff := cmp.Diff(wantBody, body); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}
}

// noticeRequest is a delivery request for a notice, which has no request id of its own.
func noticeRequest() app.DeliveryRequest {
	return app.DeliveryRequest{
		Type: "auth.notice_password_changed", Channel: "email", Locale: "en-GB",
		Recipient: "auth1:identifier:0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b",
		Variables: map[string]any{"occurred_at": "2026-10-26T10:00:00Z", "how": "changed"},
	}
}

// TestDeliveryRow checks the stored delivery requests: a challenge's keeps its request id and
// deadline, and a notice's request id is the row's id (TDD-06 §5).
func TestDeliveryRow(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)
	deadline := time.Date(2026, 10, 26, 10, 5, 0, 0, time.UTC)
	challenge := app.DeliveryRequest{
		RequestID: "0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b:2", Type: "auth.phone_verification_code",
		Channel: "sms", Locale: "en", Recipient: "auth1:identifier:0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8c",
		Variables: map[string]any{"code": "auth1:secret:0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b"},
		Deadline:  &deadline,
	}
	// A delivery needs no lock and moves no version.
	e.do(t, func(ctx context.Context) error {
		if err := e.outbox.Delivery(ctx, id, challenge); err != nil {
			return err
		}
		return e.outbox.Delivery(ctx, id, noticeRequest())
	})
	if v := e.version(t, id); v != 1 {
		t.Errorf("version = %d, want 1", v)
	}

	rows := e.rows(t)
	if len(rows) != 2 {
		t.Fatalf("outbox rows = %v, want two", rows)
	}
	bodies := make([]map[string]any, len(rows))
	for i, r := range rows {
		want := outboxRow{
			ID: r.ID, Destination: "delivery", Subject: uuid.NullUUID{UUID: id, Valid: true},
			Type: []string{challenge.Type, noticeRequest().Type}[i], Body: r.Body, Pending: true,
		}
		if diff := cmp.Diff(want, r); diff != "" {
			t.Errorf("row %d (-want +got):\n%s", i, diff)
		}
		if err := json.Unmarshal([]byte(r.Body), &bodies[i]); err != nil {
			t.Fatal(err)
		}
	}
	want := []map[string]any{
		{
			"request_id": challenge.RequestID, "type": challenge.Type, "channel": "sms", "locale": "en",
			"recipient": challenge.Recipient, "variables": map[string]any{"code": challenge.Variables["code"]},
			"deadline": "2026-10-26T10:05:00Z",
		},
		{
			"request_id": rows[1].ID.String(), "type": "auth.notice_password_changed", "channel": "email",
			"locale": "en-GB", "recipient": noticeRequest().Recipient,
			"variables": map[string]any{"occurred_at": "2026-10-26T10:00:00Z", "how": "changed"},
		},
	}
	if diff := cmp.Diff(want, bodies); diff != "" {
		t.Errorf("bodies (-want +got):\n%s", diff)
	}
}

// TestTraceContextStored checks that the writing span's W3C trace context is kept for the relay:
// in trace_context, and as the delivery request's traceparent.
func TestTraceContextStored(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3}, SpanID: trace.SpanID{4, 5, 6}, TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(t.Context(), sc)
	const traceparent = "00-01020300000000000000000000000000-0405060000000000-01"
	if err := e.uow.Do(ctx, func(ctx context.Context) error {
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		if err := e.outbox.Event(ctx, "account.password_changed", id, map[string]any{}); err != nil {
			return err
		}
		return e.outbox.Delivery(ctx, id, noticeRequest())
	}); err != nil {
		t.Fatal(err)
	}

	for _, r := range e.rows(t) {
		var tc map[string]string
		if err := json.Unmarshal([]byte(r.TraceContext.String), &tc); err != nil {
			t.Fatalf("%s trace_context %q: %v", r.Destination, r.TraceContext.String, err)
		}
		if diff := cmp.Diff(map[string]string{"traceparent": traceparent}, tc); diff != "" {
			t.Errorf("%s trace_context (-want +got):\n%s", r.Destination, diff)
		}
		if r.Destination == "delivery" {
			var body struct{ Traceparent string }
			if err := json.Unmarshal([]byte(r.Body), &body); err != nil {
				t.Fatal(err)
			}
			if body.Traceparent != traceparent {
				t.Errorf("delivery traceparent = %q, want %q", body.Traceparent, traceparent)
			}
		}
	}
}

// TestOutboxRefusals checks what the writer refuses, before writing anything: a write outside a
// transaction (I-7), an event on an account the transaction has not locked (TDD-06 §2), and data
// that is not JSON.
func TestOutboxRefusals(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)

	if err := e.outbox.Event(t.Context(), "account.deleted", id, map[string]any{}); !errors.Is(err, postgres.ErrNoTransaction) {
		t.Errorf("Event outside Do: %v, want ErrNoTransaction", err)
	}
	if err := e.outbox.Delivery(t.Context(), id, noticeRequest()); !errors.Is(err, postgres.ErrNoTransaction) {
		t.Errorf("Delivery outside Do: %v, want ErrNoTransaction", err)
	}
	for _, c := range []struct {
		name string
		fn   func(ctx context.Context) error
		want error
	}{
		{"not locked", func(ctx context.Context) error {
			return e.outbox.Event(ctx, "account.deleted", id, map[string]any{})
		}, postgres.ErrAccountNotLocked},
		{"other account locked", func(ctx context.Context) error {
			other := e.newAccount("", "")
			if err := e.repo.Create(ctx, other); err != nil {
				return err
			}
			if err := e.lock(ctx, other.ID); err != nil {
				return err
			}
			return e.outbox.Event(ctx, "account.deleted", id, map[string]any{})
		}, postgres.ErrAccountNotLocked},
	} {
		if err := e.uow.Do(t.Context(), c.fn); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	err := e.uow.Do(t.Context(), func(ctx context.Context) error {
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		return e.outbox.Event(ctx, "account.deleted", id, map[string]any{"bad": make(chan int)})
	})
	if err == nil {
		t.Error("Event with data that is not JSON succeeded")
	}
	if rows := e.rows(t); len(rows) != 0 {
		t.Errorf("outbox rows = %v, want none", rows)
	}
}

// TestConcurrentEvents checks I-8 and I-10 together: use cases that each lock one account and
// write an event get distinct versions, and the account ends at the highest.
func TestConcurrentEvents(t *testing.T) {
	t.Parallel()
	const n = 8
	e := outboxDB(t)
	id := e.account(t)

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			errs <- e.uow.Do(t.Context(), func(ctx context.Context) error {
				if err := e.lock(ctx, id); err != nil {
					return err
				}
				time.Sleep(10 * time.Millisecond)
				return e.outbox.Event(ctx, "account.profile_updated", id, map[string]any{})
			})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	want := make([]int64, n)
	for i := range want {
		want[i] = int64(i + 2)
	}
	if diff := cmp.Diff(want, e.eventVersions(t)); diff != "" {
		t.Errorf("event versions (-want +got):\n%s", diff)
	}
	if v := e.version(t, id); v != 1+n {
		t.Errorf("version = %d, want %d", v, 1+n)
	}
}

// listen returns a connection listening on the outbox channel, as superuser.
func (e *outboxEnv) listen(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(t.Context(), e.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(t.Context(), "LISTEN auth1_outbox"); err != nil {
		t.Fatal(err)
	}
	return conn
}

// notified returns the payloads that arrive on conn within wait.
func notified(ctx context.Context, t *testing.T, conn *pgx.Conn, wait time.Duration) []string {
	t.Helper()
	var got []string
	for {
		wctx, cancel := context.WithTimeout(ctx, wait)
		n, err := conn.WaitForNotification(wctx)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			return got
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, n.Payload)
	}
}

// TestNotifyOnCommit checks TDD-06 §3.3: the writing transaction notifies auth1_outbox with each
// destination it wrote, delivered at commit and never after a rollback.
func TestNotifyOnCommit(t *testing.T) {
	t.Parallel()
	e := outboxDB(t)
	id := e.account(t)
	conn := e.listen(t)

	_ = e.uow.Do(t.Context(), func(ctx context.Context) error {
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		if err := e.outbox.Event(ctx, "account.password_changed", id, map[string]any{}); err != nil {
			return err
		}
		return errors.New("use case failed")
	})
	if got := notified(t.Context(), t, conn, 300*time.Millisecond); len(got) != 0 {
		t.Errorf("notifications after a rollback = %q, want none", got)
	}

	e.do(t, func(ctx context.Context) error {
		if err := e.lock(ctx, id); err != nil {
			return err
		}
		if err := e.outbox.Event(ctx, "account.password_changed", id, map[string]any{}); err != nil {
			return err
		}
		if err := e.outbox.Delivery(ctx, id, noticeRequest()); err != nil {
			return err
		}
		if got := notified(ctx, t, conn, 300*time.Millisecond); len(got) != 0 {
			return fmt.Errorf("notifications before commit = %q, want none", got)
		}
		return nil
	})
	got := notified(t.Context(), t, conn, time.Second)
	if diff := cmp.Diff([]string{"event", "delivery"}, got); diff != "" {
		t.Errorf("notifications (-want +got):\n%s", diff)
	}
}
