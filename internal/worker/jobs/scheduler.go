package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// DefaultCheckEvery is how often a running job re-checks that this instance still leads it.
const DefaultCheckEvery = 5 * time.Second

// Elector decides which instance leads a job (postgres.Leader).
type Elector interface {
	// Lead reports whether this instance holds the job lock lock, taking it when it is free. On
	// an error the instance leads no job: the scheduler treats every lock as lost, whatever the
	// boolean. The scheduler bounds each call by its CheckEvery.
	Lead(ctx context.Context, lock int32) (bool, error)
}

// Job is a leader-elected job (TDD-08 §7).
type Job struct {
	// Name is the job's metric label (auth1_job_last_success_timestamp{job}), its log field and
	// the id of the system actor of what it writes. It holds nothing personal.
	Name string
	// Lock is the job's advisory lock id: above 0, and unique among the jobs.
	Lock int32
	// Every is the interval between runs. 0 runs the job once, when this instance first leads
	// it; a run that fails or is cancelled is tried again at the next check, until one succeeds.
	Every time.Duration
	// Run does one run. It returns when ctx ends, which happens when the instance stops or
	// loses the lead. A nil error records a success.
	Run func(ctx context.Context) error
}

// Options configure the scheduler.
type Options struct {
	// Elector and Jobs are required.
	Elector Elector
	Jobs    []Job
	// CheckEvery is how often a running job re-checks the lead, and the bound on each check;
	// zero means DefaultCheckEvery. A job not led is tried again at its interval (at CheckEvery for
	// a once job).
	CheckEvery time.Duration
	Logger     *slog.Logger
	// LastSuccess is auth1_job_last_success_timestamp; nil records nothing.
	LastSuccess metric.Float64Gauge
}

// Scheduler runs each job on the instance that leads it.
type Scheduler struct {
	o Options
}

// New returns the scheduler, or an error for a missing elector, or a job with no name or run, a
// lock not above 0, a negative interval, or a name or lock another job has. It keeps its own copy
// of the jobs.
func New(o Options) (*Scheduler, error) {
	if o.Elector == nil {
		return nil, errors.New("jobs: no elector")
	}
	names, locks := map[string]bool{}, map[int32]bool{}
	for _, j := range o.Jobs {
		switch {
		case j.Name == "":
			return nil, errors.New("jobs: a job has no name")
		case j.Run == nil:
			return nil, fmt.Errorf("jobs: job %s has no run", j.Name)
		case j.Lock <= 0:
			return nil, fmt.Errorf("jobs: job %s has lock %d, not above 0", j.Name, j.Lock)
		case j.Every < 0:
			return nil, fmt.Errorf("jobs: job %s has a negative interval", j.Name)
		case names[j.Name]:
			return nil, fmt.Errorf("jobs: job name %s repeated", j.Name)
		case locks[j.Lock]:
			return nil, fmt.Errorf("jobs: job %s repeats lock %d", j.Name, j.Lock)
		}
		names[j.Name], locks[j.Lock] = true, true
	}
	o.Jobs = slices.Clone(o.Jobs)
	if o.CheckEvery <= 0 {
		o.CheckEvery = DefaultCheckEvery
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.LastSuccess == nil {
		o.LastSuccess = noop.Float64Gauge{}
	}
	return &Scheduler{o: o}, nil
}

// Run runs the jobs until ctx ends, then returns nil once the runs in flight have returned. At
// start and at each interval, a job runs if this instance leads it. Runs of one job never
// overlap: ticks missed during a run are dropped, and the next run waits for the next tick.
func (s *Scheduler) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, j := range s.o.Jobs {
		wg.Go(func() { s.loop(ctx, j) })
	}
	wg.Wait()
	return nil
}

// loop runs one job until ctx ends, or until a once job has succeeded.
func (s *Scheduler) loop(ctx context.Context, j Job) {
	every := j.Every
	if every == 0 {
		every = s.o.CheckEvery
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	var leading atomic.Bool
	for {
		if s.lead(ctx, j, &leading) {
			if s.run(ctx, j, &leading) && j.Every == 0 {
				return
			}
			select { // drop a tick that came during the run
			case <-tick.C:
			default:
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// lead asks the elector, within CheckEvery, whether this instance leads j, and logs a change.
// An error is no lead.
func (s *Scheduler) lead(ctx context.Context, j Job, leading *atomic.Bool) bool {
	cctx, cancel := context.WithTimeout(ctx, s.o.CheckEvery)
	defer cancel()
	ok, err := s.o.Elector.Lead(cctx, j.Lock)
	if err != nil {
		ok = false
		if ctx.Err() == nil {
			s.o.Logger.Warn("job leader check failed", slog.String("job", j.Name), slog.String("error", err.Error()))
		}
	}
	if leading.Swap(ok) != ok {
		msg := "job leadership acquired"
		if !ok {
			msg = "job leadership lost"
		}
		s.o.Logger.Info(msg, slog.String("job", j.Name))
	}
	return ok
}

// run runs j once, cancelling it when a check finds the lead lost, and records a success. It
// reports whether the run succeeded: returned nil, with the lead held to the end.
func (s *Scheduler) run(ctx context.Context, j Job, leading *atomic.Bool) bool {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Go(func() {
		t := time.NewTicker(s.o.CheckEvery)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if !s.lead(rctx, j, leading) {
					cancel()
					return
				}
			}
		}
	})
	start := time.Now()
	err := j.Run(rctx)
	close(done)
	wg.Wait()
	attrs := []slog.Attr{slog.String("job", j.Name), slog.Float64("duration", time.Since(start).Seconds())}
	switch {
	case ctx.Err() != nil && (err == nil || errors.Is(err, context.Canceled)):
		return false // stopping
	case rctx.Err() != nil && ctx.Err() == nil:
		s.o.Logger.LogAttrs(ctx, slog.LevelInfo, "job run cancelled: lead lost", attrs...)
		return false
	case err != nil:
		s.o.Logger.LogAttrs(ctx, slog.LevelError, "job run failed", append(attrs, slog.String("error", err.Error()))...)
		return false
	}
	s.o.LastSuccess.Record(ctx, float64(time.Now().Unix()), metric.WithAttributes(attribute.String("job", j.Name)))
	s.o.Logger.LogAttrs(ctx, slog.LevelDebug, "job run", attrs...)
	return true
}
