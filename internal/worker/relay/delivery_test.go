package relay_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/worker/relay"
)

// call is one outcome write the fake outbox received.
type call struct {
	Op      string // publish, retry or park
	ID      uuid.UUID
	Text    string
	Delay   time.Duration
	Attempt int
}

// fakeOutbox hands out queued rows and records the outcome writes.
type fakeOutbox struct {
	mu       sync.Mutex
	queue    []app.ClaimedDelivery
	claims   []int // n of each Claim
	calls    []call
	stats    app.OutboxStats
	recorded chan struct{} // signalled after each outcome write
	claimErr error
}

func newFakeOutbox(rows ...app.ClaimedDelivery) *fakeOutbox {
	return &fakeOutbox{queue: rows, recorded: make(chan struct{}, 100)}
}

func (f *fakeOutbox) Claim(_ context.Context, n int, _ time.Duration) ([]app.ClaimedDelivery, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = append(f.claims, n)
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	k := min(n, len(f.queue))
	out := f.queue[:k]
	f.queue = f.queue[k:]
	return out, nil
}

func (f *fakeOutbox) record(c call) error {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	f.recorded <- struct{}{}
	return nil
}

func (f *fakeOutbox) Publish(_ context.Context, c app.ClaimedDelivery, lastError string) error {
	return f.record(call{Op: "publish", ID: c.Row.ID, Text: lastError, Attempt: c.Attempt})
}

func (f *fakeOutbox) Retry(_ context.Context, c app.ClaimedDelivery, delay time.Duration, reason string) error {
	return f.record(call{Op: "retry", ID: c.Row.ID, Text: reason, Delay: delay, Attempt: c.Attempt})
}

func (f *fakeOutbox) Park(_ context.Context, c app.ClaimedDelivery, reason string) error {
	return f.record(call{Op: "park", ID: c.Row.ID, Text: reason, Attempt: c.Attempt})
}

func (f *fakeOutbox) Stats(context.Context) (app.OutboxStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats, nil
}

func (f *fakeOutbox) push(rows ...app.ClaimedDelivery) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, rows...)
}

func (f *fakeOutbox) claimCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.claims)
}

// waitCalls waits for n outcome writes and returns all of them.
func (f *fakeOutbox) waitCalls(t *testing.T, n int) []call {
	t.Helper()
	for range n {
		select {
		case <-f.recorded:
		case <-time.After(5 * time.Second):
			t.Fatalf("waited 5s for %d outcome writes", n)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

// fakeDelivery answers with fn and counts the sends.
type fakeDelivery struct {
	fn func(ctx context.Context, row app.DeliveryRow) app.DeliveryOutcome
}

func (d fakeDelivery) Send(ctx context.Context, row app.DeliveryRow) app.DeliveryOutcome {
	return d.fn(ctx, row)
}

func answer(o app.DeliveryOutcome) fakeDelivery {
	return fakeDelivery{fn: func(context.Context, app.DeliveryRow) app.DeliveryOutcome { return o }}
}

// claimed is a claimed notice at attempt.
func claimed(n, attempt int) app.ClaimedDelivery {
	id := uuid.MustParse(fmt.Sprintf("00000000-0000-7000-8000-%012d", n))
	return app.ClaimedDelivery{Attempt: attempt, Row: app.DeliveryRow{ID: id, Request: app.DeliveryRequest{RequestID: id.String()}}}
}

// options are the relay's options for the fakes: no poll to speak of, fixed jitter.
func options(o app.DeliveryOutbox, d app.MessageDelivery) relay.Options {
	return relay.Options{
		Outbox: o, Delivery: d, PollInterval: time.Hour, BatchSize: 100, MaxAttempts: 3,
		Jitter: func() float64 { return 0.5 }, Logger: slog.New(slog.DiscardHandler),
	}
}

// start runs the relay until the test ends and returns its stop function, which waits for Run.
func start(t *testing.T, o relay.Options) (stop func() error) {
	t.Helper()
	r, err := relay.NewDeliveries(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	var once sync.Once
	var runErr error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case runErr = <-done:
			case <-time.After(10 * time.Second):
				runErr = errors.New("Run did not return within 10s of cancel")
			}
		})
		return runErr
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	return stop
}

func TestNewDeliveriesRefuses(t *testing.T) {
	t.Parallel()
	o := newFakeOutbox()
	d := answer(app.DeliveryOutcome{Result: app.DeliverySent})
	for name, opt := range map[string]relay.Options{
		"no outbox":            options(nil, d),
		"no delivery adapter":  options(o, nil),
		"lease within timeout": func() relay.Options { x := options(o, d); x.Lease, x.SendTimeout = time.Second, time.Second; return x }(),
	} {
		if _, err := relay.NewDeliveries(opt); err == nil {
			t.Errorf("%s: NewDeliveries succeeded", name)
		}
	}
}

// TestDeliveriesOutcomes checks TDD-06 §3.2 step 3: what the relay records for each result.
func TestDeliveriesOutcomes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		attempt int
		outcome app.DeliveryOutcome
		want    call
	}{
		{"sent", 1, app.DeliveryOutcome{Result: app.DeliverySent}, call{Op: "publish"}},
		{"dropped", 1, app.DeliveryOutcome{Result: app.DeliveryDropped, Reason: "ref closed"},
			call{Op: "publish", Text: "dropped: ref closed"}},
		{"retry", 2, app.DeliveryOutcome{Result: app.DeliveryRetry, Reason: "503"},
			call{Op: "retry", Text: "503", Delay: relay.Backoff(2, 0.5)}},
		{"retry at max attempts", 3, app.DeliveryOutcome{Result: app.DeliveryRetry, Reason: "503"},
			call{Op: "park", Text: "parked: attempts exhausted: 503"}},
		{"parked", 1, app.DeliveryOutcome{Result: app.DeliveryParked, Reason: "400"},
			call{Op: "park", Text: "parked: 400"}},
		{"no result", 1, app.DeliveryOutcome{}, call{Op: "park", Text: "parked: no outcome"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			row := claimed(1, tc.attempt)
			o := newFakeOutbox(row)
			start(t, options(o, answer(tc.outcome)))
			got := o.waitCalls(t, 1)
			want := tc.want
			want.ID, want.Attempt = row.Row.ID, tc.attempt
			if diff := cmp.Diff([]call{want}, got); diff != "" {
				t.Errorf("outcome writes (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDeliveriesClaimsOnlyIdleSenders checks the per-destination pool: a claim takes no more rows
// than there are idle senders, so a leased row never waits for one.
func TestDeliveriesClaimsOnlyIdleSenders(t *testing.T) {
	t.Parallel()
	rows := make([]app.ClaimedDelivery, 5)
	for i := range rows {
		rows[i] = claimed(i+1, 1)
	}
	o := newFakeOutbox(rows...)
	release := make(chan struct{})
	opt := options(o, fakeDelivery{fn: func(context.Context, app.DeliveryRow) app.DeliveryOutcome {
		<-release
		return app.DeliveryOutcome{Result: app.DeliverySent}
	}})
	opt.Senders = 2
	wake := make(chan struct{}, 1)
	opt.Wake = wake
	start(t, opt)
	time.Sleep(100 * time.Millisecond)
	wake <- struct{}{}
	time.Sleep(100 * time.Millisecond)
	o.mu.Lock()
	claims := append([]int(nil), o.claims...)
	o.mu.Unlock()
	if diff := cmp.Diff([]int{2}, claims); diff != "" {
		t.Errorf("claims while both senders are busy (-want +got):\n%s", diff)
	}
	close(release)
	o.waitCalls(t, len(rows))
}

// TestDeliveriesWakeOnNotify checks TDD-06 §3.3: a wake-up claims at once, without waiting for
// the poll.
func TestDeliveriesWakeOnNotify(t *testing.T) {
	t.Parallel()
	o := newFakeOutbox()
	wake := make(chan struct{}, 1)
	opt := options(o, answer(app.DeliveryOutcome{Result: app.DeliverySent}))
	opt.Wake = wake
	start(t, opt)
	deadline := time.Now().Add(5 * time.Second)
	for o.claimCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	o.push(claimed(1, 1))
	wake <- struct{}{}
	if got := o.waitCalls(t, 1); got[0].Op != "publish" {
		t.Errorf("outcome = %+v, want publish", got[0])
	}
}

// TestDeliveriesPoll checks the safety net: without a wake-up, the poll claims.
func TestDeliveriesPoll(t *testing.T) {
	t.Parallel()
	o := newFakeOutbox()
	opt := options(o, answer(app.DeliveryOutcome{Result: app.DeliverySent}))
	opt.PollInterval = 20 * time.Millisecond
	start(t, opt)
	o.push(claimed(1, 1))
	o.waitCalls(t, 1)
}

// TestDeliveriesClaimErrorKeepsRunning checks that a failed claim is retried at the next poll and
// does not stop the relay.
func TestDeliveriesClaimErrorKeepsRunning(t *testing.T) {
	t.Parallel()
	o := newFakeOutbox(claimed(1, 1))
	o.claimErr = errors.New("database down")
	opt := options(o, answer(app.DeliveryOutcome{Result: app.DeliverySent}))
	opt.PollInterval = 20 * time.Millisecond
	start(t, opt)
	time.Sleep(100 * time.Millisecond)
	o.mu.Lock()
	o.claimErr = nil
	o.mu.Unlock()
	o.waitCalls(t, 1)
}

// TestDeliveriesStopsClaimingOnCancel checks the graceful stop: once the context ends, nothing
// more is claimed, and Run returns only after the send in flight and its outcome write.
func TestDeliveriesStopsClaimingOnCancel(t *testing.T) {
	t.Parallel()
	o := newFakeOutbox(claimed(1, 1))
	sending, release := make(chan struct{}), make(chan struct{})
	opt := options(o, fakeDelivery{fn: func(ctx context.Context, _ app.DeliveryRow) app.DeliveryOutcome {
		close(sending)
		<-release
		if ctx.Err() != nil {
			return app.DeliveryOutcome{Result: app.DeliveryRetry, Reason: "send cancelled"}
		}
		return app.DeliveryOutcome{Result: app.DeliverySent}
	}})
	opt.PollInterval = 10 * time.Millisecond
	stop := start(t, opt)
	<-sending
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-stopped:
		t.Fatalf("Run returned (%v) with a send in flight", err)
	default:
	}
	before := o.claimCount()
	time.Sleep(50 * time.Millisecond)
	if after := o.claimCount(); after != before {
		t.Errorf("claims after cancel: %d, want none", after-before)
	}
	close(release)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if got := o.waitCalls(t, 1); got[0].Op != "publish" {
		t.Errorf("outcome = %+v, want the send's publish, written after cancel", got[0])
	}
}

// TestDeliveriesSendTimeout checks that a send is bounded by SendTimeout.
func TestDeliveriesSendTimeout(t *testing.T) {
	t.Parallel()
	o := newFakeOutbox(claimed(1, 1))
	opt := options(o, fakeDelivery{fn: func(ctx context.Context, _ app.DeliveryRow) app.DeliveryOutcome {
		<-ctx.Done()
		return app.DeliveryOutcome{Result: app.DeliveryRetry, Reason: "timeout"}
	}})
	opt.SendTimeout, opt.Lease = 50*time.Millisecond, 3*time.Second
	start(t, opt)
	if got := o.waitCalls(t, 1); got[0].Op != "retry" {
		t.Errorf("outcome = %+v, want retry", got[0])
	}
}

// TestDeliveriesRecordsMetrics checks TDD-08 §5.2: the backlog's age and the parked count, with
// destination delivery.
func TestDeliveriesRecordsMetrics(t *testing.T) {
	t.Parallel()
	o := newFakeOutbox()
	o.stats = app.OutboxStats{OldestAge: 42 * time.Second, Parked: 3}
	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test")
	age, err := meter.Float64Gauge("auth1_outbox_age_seconds")
	if err != nil {
		t.Fatal(err)
	}
	parked, err := meter.Float64Gauge("auth1_outbox_parked")
	if err != nil {
		t.Fatal(err)
	}
	opt := options(o, answer(app.DeliveryOutcome{Result: app.DeliverySent}))
	opt.Age, opt.Parked, opt.StatsInterval = age, parked, 10*time.Millisecond
	start(t, opt)

	want := map[string]float64{"auth1_outbox_age_seconds": 42, "auth1_outbox_parked": 3}
	var got map[string]float64
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(t.Context(), &rm); err != nil {
			t.Fatal(err)
		}
		got = map[string]float64{}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				for _, dp := range m.Data.(metricdata.Gauge[float64]).DataPoints {
					if d, _ := dp.Attributes.Value("destination"); d.AsString() == "delivery" {
						got[m.Name] = dp.Value
					}
				}
			}
		}
		if cmp.Equal(want, got) {
			return
		}
	}
	t.Errorf("gauges = %v, want %v", got, want)
}

// syncBuffer is a bytes.Buffer safe for the relay's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Count(s.b.String(), sub)
}

// TestDeliveriesLogsClaimFailureOnce checks that a database outage logs one error, not one per
// poll, and that the recovery is logged.
func TestDeliveriesLogsClaimFailureOnce(t *testing.T) {
	t.Parallel()
	o := newFakeOutbox()
	o.claimErr = errors.New("database down")
	var logs syncBuffer
	opt := options(o, answer(app.DeliveryOutcome{Result: app.DeliverySent}))
	opt.PollInterval, opt.Logger = 5*time.Millisecond, slog.New(slog.NewTextHandler(&logs, nil))
	start(t, opt)
	for deadline := time.Now().Add(5 * time.Second); o.claimCount() < 10 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if n := logs.count(`msg="claim deliveries"`); n != 1 {
		t.Errorf("%d claim errors logged over %d failed claims, want 1", n, o.claimCount())
	}
	o.mu.Lock()
	o.claimErr = nil
	o.mu.Unlock()
	for deadline := time.Now().Add(5 * time.Second); logs.count(`msg="claim deliveries recovered"`) == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the recovery was not logged")
		}
	}
}
