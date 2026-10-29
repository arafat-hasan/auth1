package argon2id

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/telemetry"
)

// semParams are small parameters for the semaphore tests.
var semParams = Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1}

// meters holds the hasher's instruments on a manual reader.
type meters struct {
	reader *sdkmetric.ManualReader
}

// newSemHasher returns a hasher with the instruments of TDD-08 §5.2 on a manual reader.
func newSemHasher(t *testing.T, maxConcurrent int, queueTimeout time.Duration) (*Hasher, *meters) {
	t.Helper()
	keys, err := crypto.ParseKeyring([]byte("keys:\n  - id: 1\n    key: AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n    state: active\n"), crypto.StateVerify)
	if err != nil {
		t.Fatal(err)
	}
	reader := sdkmetric.NewManualReader()
	m := telemetry.NewMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	o := Options{Params: semParams, MaxConcurrent: maxConcurrent, QueueTimeout: queueTimeout, Peppers: keys}
	if o.Duration, err = m.Histogram("auth1_hash_duration_seconds"); err != nil {
		t.Fatal(err)
	}
	if o.Queue, err = m.Histogram("auth1_hash_queue_seconds"); err != nil {
		t.Fatal(err)
	}
	if o.Rejected, err = m.Counter("auth1_hash_rejected_total"); err != nil {
		t.Fatal(err)
	}
	h, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return h, &meters{reader: reader}
}

// counts returns each instrument's number of recordings (histograms) or sum (counters), and fails
// the test on any data point with attributes: TDD-08 §5.2 gives these instruments none.
func (m *meters) counts(t *testing.T) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := m.reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, met := range sm.Metrics {
			switch d := met.Data.(type) {
			case metricdata.Histogram[float64]:
				for _, dp := range d.DataPoints {
					out[met.Name] += int64(dp.Count) //nolint:gosec // test counts are small
					if dp.Attributes.Len() != 0 {
						t.Errorf("%s has attributes %v", met.Name, dp.Attributes.ToSlice())
					}
				}
			case metricdata.Sum[int64]:
				for _, dp := range d.DataPoints {
					out[met.Name] += dp.Value
					if dp.Attributes.Len() != 0 {
						t.Errorf("%s has attributes %v", met.Name, dp.Attributes.ToSlice())
					}
				}
			}
		}
	}
	return out
}

// blockCompute makes h's hashes wait for release, reporting each start on entered.
func blockCompute(h *Hasher) (entered chan struct{}, release chan struct{}) {
	entered, release = make(chan struct{}, 64), make(chan struct{})
	h.compute = func(key crypto.Key, p Params, salt, password []byte) []byte {
		entered <- struct{}{}
		<-release
		return compute(key, p, salt, password)
	}
	return entered, release
}

// TestOverloaded (T-36): with every slot taken, Hash, Verify and VerifyDummy each wait
// queue_timeout and return ErrOverloaded, counted in auth1_hash_rejected_total.
func TestOverloaded(t *testing.T) {
	t.Parallel()
	const queueTimeout = 100 * time.Millisecond
	const tolerance = 900 * time.Millisecond // a loaded CI runner under -race
	h, m := newSemHasher(t, 2, queueTimeout)
	phc, kid, err := h.Hash(t.Context(), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	entered, release := blockCompute(h)
	var holders sync.WaitGroup
	for range 2 {
		holders.Go(func() {
			if _, _, err := h.Hash(context.Background(), []byte("pw")); err != nil {
				t.Error(err)
			}
		})
	}
	<-entered
	<-entered
	for name, call := range map[string]func() error{
		"Hash":        func() error { _, _, err := h.Hash(t.Context(), []byte("pw")); return err },
		"Verify":      func() error { _, _, err := h.Verify(t.Context(), phc, kid, []byte("pw")); return err },
		"VerifyDummy": func() error { _, err := h.VerifyDummy(t.Context(), []byte("pw")); return err },
	} {
		start := time.Now()
		err := call()
		took := time.Since(start)
		if !errors.Is(err, app.ErrOverloaded) {
			t.Errorf("%s = %v, want ErrOverloaded", name, err)
		}
		if took < queueTimeout || took > queueTimeout+tolerance {
			t.Errorf("%s returned after %s, want %s (+%s)", name, took, queueTimeout, tolerance)
		}
	}
	close(release)
	holders.Wait()
	got := m.counts(t)
	if got["auth1_hash_rejected_total"] != 3 {
		t.Errorf("auth1_hash_rejected_total = %d, want 3", got["auth1_hash_rejected_total"])
	}
	if len(entered) != 0 {
		t.Errorf("%d rejected calls hashed anyway", len(entered))
	}
}

// TestPeakConcurrency (T-36): however many callers, no more than max_concurrent hashes run at
// once, and the slots are used.
func TestPeakConcurrency(t *testing.T) {
	t.Parallel()
	const slots = 3
	h, _ := newSemHasher(t, slots, 30*time.Second)
	phc, kid, err := h.Hash(t.Context(), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	var inFlight, peak atomic.Int32
	h.compute = func(key crypto.Key, p Params, salt, password []byte) []byte {
		n := inFlight.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond) // long enough for callers to pile up
		defer inFlight.Add(-1)
		return compute(key, p, salt, password)
	}
	var callers sync.WaitGroup
	for i := range 24 {
		callers.Go(func() {
			var err error
			switch i % 3 {
			case 0:
				_, _, err = h.Hash(t.Context(), []byte("pw"))
			case 1:
				_, _, err = h.Verify(t.Context(), phc, kid, []byte("pw"))
			default:
				_, err = h.VerifyDummy(t.Context(), []byte("pw"))
			}
			if err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if p := peak.Load(); p != slots {
		t.Errorf("peak concurrent hashes = %d, want %d", p, slots)
	}
}

// TestQueueCancel: a caller whose context ends while it waits gets the context's error at once,
// not ErrOverloaded, and is not counted as rejected.
func TestQueueCancel(t *testing.T) {
	t.Parallel()
	h, m := newSemHasher(t, 1, 5*time.Second)
	entered, release := blockCompute(h)
	var holder sync.WaitGroup
	holder.Go(func() { _, _, _ = h.Hash(context.Background(), []byte("pw")) })
	<-entered
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(20*time.Millisecond, cancel)
	start := time.Now()
	_, _, err := h.Hash(ctx, []byte("pw"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Hash = %v, want context.Canceled", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("Hash returned after %s, want soon after the cancellation", took)
	}
	close(release)
	holder.Wait()

	done, stop := context.WithCancel(t.Context())
	stop()
	if _, err := h.VerifyDummy(done, []byte("pw")); !errors.Is(err, context.Canceled) {
		t.Errorf("VerifyDummy with an ended context and a free slot = %v, want context.Canceled", err)
	}
	if got := m.counts(t)["auth1_hash_rejected_total"]; got != 0 {
		t.Errorf("auth1_hash_rejected_total = %d, want 0", got)
	}
}

// TestMetricsRecorded: a hash records one duration and one queue wait, without attributes.
func TestMetricsRecorded(t *testing.T) {
	t.Parallel()
	h, m := newSemHasher(t, 1, time.Second)
	if _, _, err := h.Hash(t.Context(), []byte("pw")); err != nil {
		t.Fatal(err)
	}
	got := m.counts(t)
	if got["auth1_hash_duration_seconds"] != 1 || got["auth1_hash_queue_seconds"] != 1 {
		t.Errorf("counts = %v, want one duration and one queue wait", got)
	}
}
