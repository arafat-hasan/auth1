package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/arafat-hasan/auth1/internal/app"
)

// Defaults of the delivery relay. TDD-06 names no configuration for them.
const (
	// DefaultSenders is how many deliveries one relay sends at once: the pool of the delivery
	// destination, apart from the event relay's (TDD-06 §9).
	DefaultSenders = 8
	// DefaultSendTimeout bounds one MessageDelivery.Send.
	DefaultSendTimeout = 10 * time.Second
	// DefaultLease is how long a claimed row stays leased: past a send and its outcome write, so a
	// row is claimed again only when its relay has died or stalled.
	DefaultLease = 30 * time.Second
	// DefaultStatsInterval is how often the backlog gauges are refreshed.
	DefaultStatsInterval = 15 * time.Second
)

// outcomeTimeout bounds an outcome write, which runs even after the relay's context has ended.
const outcomeTimeout = 2 * time.Second

// destination labels the delivery relay's gauges (TDD-08 §5.2).
var destination = metric.WithAttributeSet(attribute.NewSet(attribute.String("destination", "delivery")))

// Options configure the delivery relay.
type Options struct {
	// Outbox and Delivery are required.
	Outbox   app.DeliveryOutbox
	Delivery app.MessageDelivery
	// Wake is signalled when deliveries may be due (the LISTEN channel); nil polls only.
	Wake <-chan struct{}
	// PollInterval, BatchSize and MaxAttempts are outbox.poll_interval, batch_size and
	// max_attempts.
	PollInterval time.Duration
	BatchSize    int
	MaxAttempts  int
	// Senders, SendTimeout, Lease and StatsInterval default, when zero, to the constants above.
	// Lease must exceed SendTimeout plus the outcome write.
	Senders       int
	SendTimeout   time.Duration
	Lease         time.Duration
	StatsInterval time.Duration
	// Jitter returns a value in [-1, 1] for Backoff; nil draws it at random.
	Jitter func() float64
	Logger *slog.Logger
	// Age and Parked are auth1_outbox_age_seconds and auth1_outbox_parked; nil records nothing.
	Age, Parked metric.Float64Gauge
}

// Deliveries relays delivery rows to the MessageDelivery adapter (TDD-06 §3.2).
type Deliveries struct {
	o Options
	// claimFailing is set while claims fail, so an outage is logged once, not at every poll. Only
	// Run's goroutine reads and writes it.
	claimFailing bool
}

// NewDeliveries returns the delivery relay. It refuses a missing outbox or adapter: the
// deployment would otherwise accept messages it never sends.
func NewDeliveries(o Options) (*Deliveries, error) {
	if o.Outbox == nil {
		return nil, errors.New("delivery relay: no outbox")
	}
	if o.Delivery == nil {
		return nil, errors.New("delivery relay: no delivery adapter")
	}
	if o.Senders <= 0 {
		o.Senders = DefaultSenders
	}
	if o.SendTimeout <= 0 {
		o.SendTimeout = DefaultSendTimeout
	}
	if o.Lease <= 0 {
		o.Lease = DefaultLease
	}
	if o.StatsInterval <= 0 {
		o.StatsInterval = DefaultStatsInterval
	}
	if o.Lease <= o.SendTimeout+outcomeTimeout {
		return nil, fmt.Errorf("delivery relay: lease %v must exceed the send timeout %v plus %v", o.Lease, o.SendTimeout, outcomeTimeout)
	}
	if o.BatchSize <= 0 || o.MaxAttempts <= 0 || o.PollInterval <= 0 {
		return nil, errors.New("delivery relay: poll interval, batch size and max attempts must be positive")
	}
	if o.Jitter == nil {
		o.Jitter = func() float64 { return 2*rand.Float64() - 1 } //nolint:gosec // jitter, not a secret
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Age == nil {
		o.Age = noop.Float64Gauge{}
	}
	if o.Parked == nil {
		o.Parked = noop.Float64Gauge{}
	}
	return &Deliveries{o: o}, nil
}

// Run relays until ctx ends, then stops claiming and returns nil once the sends in flight have
// finished and been recorded: at most SendTimeout plus the outcome write. A send cut short by a
// crash is sent again by another replica when its lease ends.
func (d *Deliveries) Run(ctx context.Context) error {
	busy := make(chan struct{}, d.o.Senders) // one token per send in flight
	freed := make(chan struct{}, 1)          // a sender finished: claim again
	var wg sync.WaitGroup
	defer wg.Wait()

	poll := time.NewTicker(d.o.PollInterval)
	defer poll.Stop()
	stats := time.NewTicker(d.o.StatsInterval)
	defer stats.Stop()
	d.recordStats(ctx)

	for {
		d.claim(ctx, busy, freed, &wg)
		select {
		case <-ctx.Done():
			return nil
		case <-d.o.Wake:
		case <-poll.C:
		case <-freed:
		case <-stats.C:
			d.recordStats(ctx)
		}
	}
}

// claim claims rows for the idle senders and starts a send for each, until a claim comes back
// short or every sender is busy.
func (d *Deliveries) claim(ctx context.Context, busy chan struct{}, freed chan struct{}, wg *sync.WaitGroup) {
	for ctx.Err() == nil {
		n := min(cap(busy)-len(busy), d.o.BatchSize)
		if n == 0 {
			return
		}
		claim, err := d.o.Outbox.Claim(ctx, n, d.o.Lease)
		if err != nil {
			if ctx.Err() == nil && !d.claimFailing {
				d.claimFailing = true
				d.o.Logger.Error("claim deliveries", slog.Any("error", err))
			}
			return
		}
		if d.claimFailing {
			d.claimFailing = false
			d.o.Logger.Info("claim deliveries recovered")
		}
		for _, id := range claim.Invalid {
			d.logParked(ctx, id.String(), "", "parked: body invalid")
		}
		for _, c := range claim.Rows {
			busy <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.send(ctx, c)
				<-busy
				select {
				case freed <- struct{}{}:
				default:
				}
			}()
		}
		// A claim that locked fewer rows than asked found no more due. One that locked as many may
		// have dropped them all, with more due behind them: claim again.
		if claim.Locked < n {
			return
		}
	}
}

// send hands the row to the adapter and records the outcome (TDD-06 §3.2 step 3). Both outlive
// ctx, within their own timeouts, so a stop does not abandon a send half done.
func (d *Deliveries) send(ctx context.Context, c app.ClaimedDelivery) {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.o.SendTimeout)
	out := d.o.Delivery.Send(sctx, c.Row)
	cancel()

	octx, cancel := context.WithTimeout(context.WithoutCancel(ctx), outcomeTimeout)
	defer cancel()
	var err error
	switch out.Result {
	case app.DeliverySent:
		err = d.o.Outbox.Publish(octx, c, "")
	case app.DeliveryDropped:
		err = d.o.Outbox.Publish(octx, c, "dropped: "+out.Reason)
	case app.DeliveryRetry:
		if c.Attempt >= d.o.MaxAttempts {
			err = d.park(octx, c, "parked: attempts exhausted: "+out.Reason)
			break
		}
		err = d.o.Outbox.Retry(octx, c, Backoff(c.Attempt, d.o.Jitter()), out.Reason)
	case app.DeliveryParked:
		err = d.park(octx, c, "parked: "+out.Reason)
	default:
		// The zero outcome: the adapter did not say what happened, so the row is not published.
		err = d.park(octx, c, "parked: no outcome")
	}
	switch {
	case errors.Is(err, app.ErrClaimLost):
		d.o.Logger.Info("delivery claim lost before its outcome was recorded", slog.String("row", c.Row.ID.String()))
	case err != nil:
		// The row stays leased, and is retried when the lease ends.
		d.o.Logger.Error("record delivery outcome", slog.String("row", c.Row.ID.String()), slog.Any("error", err))
	}
}

// park parks the row and logs it: a parked row needs an operator (TDD-08 §6.5).
func (d *Deliveries) park(ctx context.Context, c app.ClaimedDelivery, reason string) error {
	if err := d.o.Outbox.Park(ctx, c, reason); err != nil {
		return err
	}
	d.logParked(ctx, c.Row.ID.String(), c.Row.Request.Type, reason)
	return nil
}

// logParked logs a parked row; typ is empty when the body could not be read. The reason names
// references and statuses, never values (G-6).
func (d *Deliveries) logParked(ctx context.Context, row, typ, reason string) {
	attrs := []slog.Attr{slog.String("row", row)}
	if typ != "" {
		attrs = append(attrs, slog.String("type", typ))
	}
	attrs = append(attrs, slog.String("reason", reason))
	d.o.Logger.LogAttrs(ctx, slog.LevelWarn, "delivery parked", attrs...)
}

// recordStats refreshes the backlog gauges. A failure is logged and the gauges keep their values.
func (d *Deliveries) recordStats(ctx context.Context) {
	st, err := d.o.Outbox.Stats(ctx)
	if err != nil {
		if ctx.Err() == nil {
			d.o.Logger.Error("read delivery backlog", slog.Any("error", err))
		}
		return
	}
	d.o.Age.Record(ctx, st.OldestAge.Seconds(), destination)
	d.o.Parked.Record(ctx, float64(st.Parked), destination)
}
