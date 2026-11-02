package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

var _ app.DeliveryOutbox = (*postgres.DeliveryOutbox)(nil)

// relayEnv is flowsEnv with the outbox writer and the relay's view of the outbox.
type relayEnv struct {
	*flowsEnv
	outbox *postgres.Outbox
	relay  *postgres.DeliveryOutbox
}

func relayDB(t *testing.T) *relayEnv {
	t.Helper()
	e := flowsDB(t)
	return &relayEnv{flowsEnv: e, outbox: postgres.NewOutbox(e.app, e.ids), relay: postgres.NewDeliveryOutbox(e.app, e.uow)}
}

// notice writes a notice to the account's first identifier and returns the row id.
func (e *relayEnv) notice(t *testing.T, accountID uuid.UUID) uuid.UUID {
	t.Helper()
	identifierID, _ := e.identifierOf(t, accountID)
	return e.write(t, accountID, app.DeliveryRequest{
		Type: "auth.notice_password_changed", Channel: "email", Locale: "en",
		Recipient: app.IdentifierRef(identifierID),
		Variables: map[string]any{"occurred_at": "2026-11-02T10:00:00Z", "how": "reset"},
	})
}

// challengeMessage opens an OTP challenge in a new flow of a new account and writes its message;
// it returns the challenge id and the row id.
func (e *relayEnv) challengeMessage(t *testing.T) (challengeID, rowID uuid.UUID) {
	t.Helper()
	accountID := e.flowAccount(t)
	f := e.newFlow(accountID, flow.KindRegistration, handle(accountID.String()))
	e.open(t, f)
	identifierID, value := e.identifierOf(t, accountID)
	c := e.otpChallenge(f.ID, identifierID, value, "123456")
	e.openChallenges(t, f, c)
	deadline := c.ExpiresAt
	return c.ID, e.write(t, accountID, app.DeliveryRequest{
		RequestID: c.ID.String() + ":1", Type: "auth.sign_in_code", Channel: "email", Locale: "en",
		Recipient: app.IdentifierRef(identifierID),
		Variables: map[string]any{"code": app.SecretRef(c.ID)}, Deadline: &deadline,
	})
}

// write writes req in its own transaction and returns the new row's id.
func (e *relayEnv) write(t *testing.T, accountID uuid.UUID, req app.DeliveryRequest) uuid.UUID {
	t.Helper()
	e.do(t, func(ctx context.Context) error { return e.outbox.Delivery(ctx, accountID, req) })
	var id uuid.UUID
	if err := e.su.QueryRowContext(t.Context(), "SELECT id FROM outbox ORDER BY id DESC LIMIT 1").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// claim claims up to 100 rows for lease and returns them by row id.
func (e *relayEnv) claim(t *testing.T, lease time.Duration) map[uuid.UUID]app.ClaimedDelivery {
	t.Helper()
	cs, err := e.relay.Claim(t.Context(), 100, lease)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uuid.UUID]app.ClaimedDelivery{}
	for _, c := range cs {
		out[c.Row.ID] = c
	}
	return out
}

// deliveryState is the part of a delivery row the relay changes.
type deliveryState struct {
	Attempts  int
	Published bool
	Parked    bool
	LastError string
	DueIn     time.Duration // next_attempt_at - now(), to the second
}

func (e *relayEnv) state(t *testing.T, id uuid.UUID) deliveryState {
	t.Helper()
	var s deliveryState
	var due float64
	err := e.su.QueryRowContext(t.Context(), `
		SELECT attempts, published_at IS NOT NULL, parked_at IS NOT NULL, coalesce(last_error, ''),
		       extract(epoch FROM next_attempt_at - now())
		FROM outbox WHERE id = ?`, id).Scan(&s.Attempts, &s.Published, &s.Parked, &s.LastError, &due)
	if err != nil {
		t.Fatal(err)
	}
	s.DueIn = time.Duration(due * float64(time.Second)).Round(time.Second)
	return s
}

// TestDeliveryClaimLeases checks the lease (TDD-06 §3.2): a claimed row carries its request, its
// attempts grow by one, and it is not claimed again until the lease ends.
func TestDeliveryClaimLeases(t *testing.T) {
	t.Parallel()
	e := relayDB(t)
	accountID := e.flowAccount(t)
	id := e.notice(t, accountID)

	got := e.claim(t, time.Minute)
	c, ok := got[id]
	if !ok || len(got) != 1 {
		t.Fatalf("claim = %v, want the notice", got)
	}
	identifierID, _ := e.identifierOf(t, accountID)
	want := app.ClaimedDelivery{Attempt: 1, Row: app.DeliveryRow{ID: id, AccountID: accountID, Request: app.DeliveryRequest{
		RequestID: id.String(), Type: "auth.notice_password_changed", Channel: "email", Locale: "en",
		Recipient: app.IdentifierRef(identifierID),
		Variables: map[string]any{"occurred_at": "2026-11-02T10:00:00Z", "how": "reset"},
	}}}
	if diff := cmp.Diff(want, c); diff != "" {
		t.Errorf("claimed (-want +got):\n%s", diff)
	}
	if again := e.claim(t, time.Minute); len(again) != 0 {
		t.Errorf("second claim = %v, want none while leased", again)
	}
	if s := e.state(t, id); s.Attempts != 1 || s.DueIn != time.Minute || s.Published || s.Parked {
		t.Errorf("row = %+v, want attempts 1, due in 1m, pending", s)
	}
}

// TestDeliveryClaimDecodesIntegers checks that an integer variable comes back as an integer, not
// a float, so the adapter sends it as written.
func TestDeliveryClaimDecodesIntegers(t *testing.T) {
	t.Parallel()
	e := relayDB(t)
	accountID := e.flowAccount(t)
	identifierID, _ := e.identifierOf(t, accountID)
	id := e.write(t, accountID, app.DeliveryRequest{
		Type: "auth.notice_recovery_codes", Channel: "email", Locale: "en", Recipient: app.IdentifierRef(identifierID),
		Variables: map[string]any{"change": "used", "remaining_codes": 7},
	})
	c := e.claim(t, time.Minute)[id]
	if v, ok := c.Row.Request.Variables["remaining_codes"].(int64); !ok || v != 7 {
		t.Errorf("remaining_codes = %#v, want int64 7", c.Row.Request.Variables["remaining_codes"])
	}
}

// TestDeliveryClaimSkipsLocked checks FOR UPDATE SKIP LOCKED: a row another transaction holds is
// skipped at once, not waited for.
func TestDeliveryClaimSkipsLocked(t *testing.T) {
	t.Parallel()
	e := relayDB(t)
	held := e.notice(t, e.flowAccount(t))
	free := e.notice(t, e.flowAccount(t))

	tx, err := e.su.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), "SELECT 1 FROM outbox WHERE id = ? FOR UPDATE", held); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	cs, err := e.relay.Claim(ctx, 100, time.Minute)
	if err != nil {
		t.Fatalf("claim while a row is locked: %v", err)
	}
	if len(cs) != 1 || cs[0].Row.ID != free {
		t.Errorf("claim = %v, want only the unlocked row", cs)
	}
}

// TestDeliveryClaimDropsClosedChallenge checks TDD-06 §3.2 step 1: a message whose challenge is
// not open (§6 rule 2) is published unsent with 'dropped: challenge closed'.
func TestDeliveryClaimDropsClosedChallenge(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		change string // run as superuser on the challenge, $1 its id; empty: left open
		drop   bool
	}{
		{"open", "", false},
		{"closed", "UPDATE challenges SET closed_at = now(), secret = NULL WHERE id = ?", true},
		{"expired", "UPDATE challenges SET expires_at = now() - interval '1 second' WHERE id = ?", true},
		{"out of attempts", "UPDATE challenges SET attempts = max_attempts WHERE id = ?", true},
		{"purged", "DELETE FROM challenges WHERE id = ?", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := relayDB(t)
			challengeID, id := e.challengeMessage(t)
			if tc.change != "" {
				e.exec(t, tc.change, challengeID)
			}
			_, claimed := e.claim(t, time.Minute)[id]
			s := e.state(t, id)
			if tc.drop {
				if claimed || !s.Published || s.LastError != "dropped: challenge closed" || s.Attempts != 0 {
					t.Errorf("claimed %v, row %+v; want dropped unclaimed", claimed, s)
				}
				return
			}
			if !claimed || s.Published {
				t.Errorf("claimed %v, row %+v; want claimed", claimed, s)
			}
		})
	}
}

// TestDeliveryClaimDropsOldNotice checks TDD-06 §3.2 step 1: a notice is dropped after 24 h.
func TestDeliveryClaimDropsOldNotice(t *testing.T) {
	t.Parallel()
	e := relayDB(t)
	old := e.notice(t, e.flowAccount(t))
	recent := e.notice(t, e.flowAccount(t))
	e.exec(t, "UPDATE outbox SET created_at = now() - interval '25 hours' WHERE id = ?", old)
	e.exec(t, "UPDATE outbox SET created_at = now() - interval '23 hours' WHERE id = ?", recent)

	got := e.claim(t, time.Minute)
	if _, ok := got[old]; ok {
		t.Error("the 25-hour-old notice was claimed")
	}
	if _, ok := got[recent]; !ok {
		t.Error("the 23-hour-old notice was not claimed")
	}
	if s := e.state(t, old); !s.Published || s.LastError != "dropped: notice expired" {
		t.Errorf("old notice = %+v, want dropped: notice expired", s)
	}
}

// TestDeliveryClaimParksInvalidBody checks that a row whose body is not a delivery request is
// parked, neither sent nor retried.
func TestDeliveryClaimParksInvalidBody(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"float variable":   `{"request_id":"r","type":"t","channel":"email","locale":"en","recipient":"auth1:identifier:x","variables":{"n":1.5}}`,
		"no recipient":     `{"request_id":"r","type":"t","channel":"email","locale":"en","variables":{}}`,
		"challenge not id": `{"request_id":"nope:1","type":"t","channel":"email","locale":"en","recipient":"auth1:identifier:x","variables":{}}`,
		"not an object":    `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := relayDB(t)
			id := uuid.New()
			e.exec(t, `INSERT INTO outbox (id, destination, type, body, created_at, next_attempt_at)
				VALUES (?, 'delivery', 't', ?::jsonb, now(), now())`, id, body)
			if got := e.claim(t, time.Minute); len(got) != 0 {
				t.Errorf("claim = %v, want none", got)
			}
			if s := e.state(t, id); !s.Parked || s.Published || s.LastError != "parked: body invalid" {
				t.Errorf("row = %+v, want parked: body invalid", s)
			}
		})
	}
}

// TestDeliveryLeaseExpires checks the recovery of a relay that died mid-send: once the lease
// ends, the row is claimed again, its attempts counting the lost try.
func TestDeliveryLeaseExpires(t *testing.T) {
	t.Parallel()
	e := relayDB(t)
	id := e.notice(t, e.flowAccount(t))
	if _, ok := e.claim(t, 0)[id]; !ok {
		t.Fatal("first claim missed the row")
	}
	c, ok := e.claim(t, time.Minute)[id]
	if !ok || c.Attempt != 2 {
		t.Errorf("second claim = %+v (found %v), want attempt 2", c, ok)
	}
}

// TestDeliveryStaleClaimIgnored checks the fence: an outcome written under a claim whose lease
// ran out, after the row was claimed again, changes nothing and reports ErrClaimLost.
func TestDeliveryStaleClaimIgnored(t *testing.T) {
	t.Parallel()
	e := relayDB(t)
	id := e.notice(t, e.flowAccount(t))
	stale := e.claim(t, 0)[id]
	fresh := e.claim(t, time.Minute)[id]

	for name, write := range map[string]func(app.ClaimedDelivery) error{
		"publish": func(c app.ClaimedDelivery) error { return e.relay.Publish(t.Context(), c, "") },
		"retry":   func(c app.ClaimedDelivery) error { return e.relay.Retry(t.Context(), c, time.Second, "x") },
		"park":    func(c app.ClaimedDelivery) error { return e.relay.Park(t.Context(), c, "x") },
	} {
		if err := write(stale); !errors.Is(err, app.ErrClaimLost) {
			t.Errorf("%s with a stale claim = %v, want ErrClaimLost", name, err)
		}
	}
	if s := e.state(t, id); s.Published || s.Parked || s.Attempts != 2 || s.DueIn != time.Minute {
		t.Errorf("row = %+v, want still leased to the fresh claim", s)
	}
	if err := e.relay.Publish(t.Context(), fresh, ""); err != nil {
		t.Errorf("publish with the fresh claim: %v", err)
	}
	if err := e.relay.Publish(t.Context(), fresh, ""); !errors.Is(err, app.ErrClaimLost) {
		t.Errorf("publish twice = %v, want ErrClaimLost", err)
	}
}

// TestDeliveryOutcomes checks the outcome writes of TDD-06 §3.2 step 3.
func TestDeliveryOutcomes(t *testing.T) {
	t.Parallel()
	e := relayDB(t)
	sent, dropped, parked := e.notice(t, e.flowAccount(t)), e.notice(t, e.flowAccount(t)), e.notice(t, e.flowAccount(t))
	cs := e.claim(t, time.Minute)
	if err := e.relay.Publish(t.Context(), cs[sent], ""); err != nil {
		t.Fatal(err)
	}
	if err := e.relay.Publish(t.Context(), cs[dropped], "dropped: capture: auth1:identifier:x is closed"); err != nil {
		t.Fatal(err)
	}
	if err := e.relay.Park(t.Context(), cs[parked], "parked: 400"); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[uuid.UUID]deliveryState{
		sent:    {Attempts: 1, Published: true, DueIn: time.Minute},
		dropped: {Attempts: 1, Published: true, LastError: "dropped: capture: auth1:identifier:x is closed", DueIn: time.Minute},
		parked:  {Attempts: 1, Parked: true, LastError: "parked: 400", DueIn: time.Minute},
	} {
		if diff := cmp.Diff(want, e.state(t, id)); diff != "" {
			t.Errorf("row (-want +got):\n%s", diff)
		}
	}
}

// TestDeliveryRetryCappedAtDeadline checks TDD-06 §3.2: a retry is due after the delay, but no
// later than the challenge's expiry; a notice has no cap.
func TestDeliveryRetryCappedAtDeadline(t *testing.T) {
	t.Parallel()
	e := relayDB(t)
	_, msg := e.challengeMessage(t)
	notice := e.notice(t, e.flowAccount(t))
	var deadline time.Time
	if err := e.su.QueryRowContext(t.Context(), "SELECT now() + interval '3 seconds'").Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	deadline = deadline.UTC().Truncate(time.Microsecond)
	e.exec(t, "UPDATE outbox SET body = jsonb_set(body, '{deadline}', to_jsonb(?::text)) WHERE id = ?",
		deadline.Format(time.RFC3339Nano), msg)

	cs := e.claim(t, time.Minute)
	if err := e.relay.Retry(t.Context(), cs[msg], 5*time.Minute, "capture: resolver unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := e.relay.Retry(t.Context(), cs[notice], 5*time.Minute, "capture: resolver unavailable"); err != nil {
		t.Fatal(err)
	}
	var due time.Time
	if err := e.su.QueryRowContext(t.Context(), "SELECT next_attempt_at FROM outbox WHERE id = ?", msg).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if !due.Equal(deadline) {
		t.Errorf("challenge message due %v, want the deadline %v", due, deadline)
	}
	if s := e.state(t, notice); s.DueIn != 5*time.Minute || s.LastError != "capture: resolver unavailable" || s.Published || s.Parked {
		t.Errorf("notice = %+v, want due in 5m, pending", s)
	}
}

// TestDeliveryStats checks the backlog the relay reports: the oldest pending row's age and the
// parked count, of deliveries only.
func TestDeliveryStats(t *testing.T) {
	t.Parallel()
	e := relayDB(t)
	if st, err := e.relay.Stats(t.Context()); err != nil || st != (app.OutboxStats{}) {
		t.Fatalf("empty stats = %+v, %v; want zero", st, err)
	}
	pending := e.notice(t, e.flowAccount(t))
	parked := e.notice(t, e.flowAccount(t))
	e.exec(t, "UPDATE outbox SET created_at = now() - interval '10 seconds' WHERE id = ?", pending)
	e.exec(t, "UPDATE outbox SET created_at = now() - interval '1 hour', parked_at = now() WHERE id = ?", parked)
	// An event row is not the delivery relay's.
	accountID := e.flowAccount(t)
	e.exec(t, `INSERT INTO outbox (id, destination, subject, account_version, type, body, created_at, next_attempt_at)
		VALUES (?, 'event', ?, 1, 'x', '{}', now() - interval '1 day', now())`, uuid.New(), accountID)

	st, err := e.relay.Stats(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if st.Parked != 1 || st.OldestAge.Round(time.Second) != 10*time.Second {
		t.Errorf("stats = %+v, want 10s and 1 parked", st)
	}
}
