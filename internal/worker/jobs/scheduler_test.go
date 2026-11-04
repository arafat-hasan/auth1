package jobs_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/arafat-hasan/auth1/internal/worker/jobs"
)

// elector is a fake jobs.Elector whose answer the test sets.
type elector struct {
	mu    sync.Mutex
	lead  bool
	err   error
	calls int
}

func (e *elector) Lead(context.Context, int32) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return e.lead, e.err
}

func (e *elector) set(lead bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lead = lead
}

// gauge returns the job's last-success value and whether one was recorded.
func gauge(t *testing.T, r *sdkmetric.ManualReader, job string) (float64, bool) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			g, ok := m.Data.(metricdata.Gauge[float64])
			if m.Name != "auth1_job_last_success_timestamp" || !ok {
				continue
			}
			for _, p := range g.DataPoints {
				if v, _ := p.Attributes.Value(attribute.Key("job")); v.AsString() == job {
					return p.Value, true
				}
			}
		}
	}
	return 0, false
}

// start runs a scheduler of the jobs on el until the test ends, and returns its metric reader.
func start(t *testing.T, el jobs.Elector, js ...jobs.Job) (*sdkmetric.ManualReader, context.CancelFunc) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	g, err := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("test").
		Float64Gauge("auth1_job_last_success_timestamp")
	if err != nil {
		t.Fatal(err)
	}
	s, err := jobs.New(jobs.Options{Elector: el, Jobs: js, CheckEvery: 10 * time.Millisecond, LastSuccess: g})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run = %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after its context ended")
		}
	}
	t.Cleanup(stop)
	return reader, stop
}

// eventually fails the test unless cond holds within d.
func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %v: %s", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// counting is a job body counting its runs.
type counting struct{ runs atomic.Int64 }

func (c *counting) run(context.Context) error { c.runs.Add(1); return nil }

func TestSchedulerFollowerNeverRuns(t *testing.T) {
	t.Parallel()
	el := &elector{}
	var c counting
	reader, stop := start(t, el, jobs.Job{Name: "flow-expiry", Lock: 1, Every: 10 * time.Millisecond, Run: c.run})
	eventually(t, time.Second, "several elections", func() bool { el.mu.Lock(); defer el.mu.Unlock(); return el.calls >= 5 })
	stop()
	if n := c.runs.Load(); n != 0 {
		t.Errorf("a follower ran %d times", n)
	}
	if _, ok := gauge(t, reader, "flow-expiry"); ok {
		t.Error("a follower recorded a success")
	}
}

func TestSchedulerLeaderRunsAndRecords(t *testing.T) {
	t.Parallel()
	el := &elector{lead: true}
	var c counting
	before := float64(time.Now().Unix())
	reader, _ := start(t, el, jobs.Job{Name: "flow-expiry", Lock: 1, Every: 10 * time.Millisecond, Run: c.run})
	eventually(t, time.Second, "three runs", func() bool { return c.runs.Load() >= 3 })
	v, ok := gauge(t, reader, "flow-expiry")
	if !ok || v < before || v > float64(time.Now().Unix())+1 {
		t.Errorf("auth1_job_last_success_timestamp{job=flow-expiry} = %v, %v; want about now", v, ok)
	}
}

func TestSchedulerFailureRecordsNothing(t *testing.T) {
	t.Parallel()
	el := &elector{lead: true}
	var runs atomic.Int64
	reader, stop := start(t, el, jobs.Job{Name: "flow-expiry", Lock: 1, Every: 10 * time.Millisecond,
		Run: func(context.Context) error { runs.Add(1); return errors.New("down") }})
	eventually(t, time.Second, "two runs", func() bool { return runs.Load() >= 2 })
	stop()
	if _, ok := gauge(t, reader, "flow-expiry"); ok {
		t.Error("a failed run recorded a success")
	}
}

func TestSchedulerLostMidRunCancels(t *testing.T) {
	t.Parallel()
	el := &elector{lead: true}
	running, cancelled := make(chan struct{}, 1), make(chan struct{}, 1)
	start(t, el, jobs.Job{Name: "flow-expiry", Lock: 1, Every: time.Hour, Run: func(ctx context.Context) error {
		running <- struct{}{}
		<-ctx.Done()
		cancelled <- struct{}{}
		return ctx.Err()
	}})
	<-running
	el.set(false)
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the run went on after leadership was lost")
	}
}

func TestSchedulerNoOverlap(t *testing.T) {
	t.Parallel()
	el := &elector{lead: true}
	var now, most, runs atomic.Int64
	start(t, el, jobs.Job{Name: "flow-expiry", Lock: 1, Every: 5 * time.Millisecond, Run: func(context.Context) error {
		n := now.Add(1)
		for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
		}
		time.Sleep(30 * time.Millisecond)
		now.Add(-1)
		runs.Add(1)
		return nil
	}})
	eventually(t, 3*time.Second, "four runs", func() bool { return runs.Load() >= 4 })
	if m := most.Load(); m != 1 {
		t.Errorf("%d runs at once, want 1", m)
	}
}

func TestSchedulerOnce(t *testing.T) {
	t.Parallel()
	el := &elector{}
	var c counting
	start(t, el, jobs.Job{Name: "bootstrap", Lock: 6, Run: c.run})
	time.Sleep(50 * time.Millisecond)
	if c.runs.Load() != 0 {
		t.Fatal("a once job ran without leading")
	}
	el.set(true)
	eventually(t, 2*time.Second, "the once job", func() bool { return c.runs.Load() == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := c.runs.Load(); n != 1 {
		t.Errorf("once job ran %d times", n)
	}
}

func TestSchedulerJobsIndependent(t *testing.T) {
	t.Parallel()
	el := &elector{lead: true}
	var a, b counting
	start(t, el,
		jobs.Job{Name: "a", Lock: 1, Every: 10 * time.Millisecond, Run: a.run},
		jobs.Job{Name: "b", Lock: 2, Every: 10 * time.Millisecond, Run: b.run})
	eventually(t, time.Second, "both jobs", func() bool { return a.runs.Load() >= 2 && b.runs.Load() >= 2 })
}

func TestNewRefuses(t *testing.T) {
	t.Parallel()
	ok := func(context.Context) error { return nil }
	job := jobs.Job{Name: "flow-expiry", Lock: 1, Every: time.Minute, Run: ok}
	for name, o := range map[string]jobs.Options{
		"no elector":     {Jobs: []jobs.Job{job}},
		"no name":        {Elector: &elector{}, Jobs: []jobs.Job{{Lock: 1, Run: ok}}},
		"no run":         {Elector: &elector{}, Jobs: []jobs.Job{{Name: "x", Lock: 1}}},
		"negative every": {Elector: &elector{}, Jobs: []jobs.Job{{Name: "x", Lock: 1, Every: -time.Second, Run: ok}}},
		"repeated name":  {Elector: &elector{}, Jobs: []jobs.Job{job, {Name: "flow-expiry", Lock: 2, Run: ok}}},
		"repeated lock":  {Elector: &elector{}, Jobs: []jobs.Job{job, {Name: "purge", Lock: 1, Run: ok}}},
	} {
		if _, err := jobs.New(o); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := jobs.New(jobs.Options{Elector: &elector{}, Jobs: []jobs.Job{job}}); err != nil {
		t.Errorf("valid options: %v", err)
	}
}
