package telemetry

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

// meterName is the instrumentation scope of the catalogue instruments.
const meterName = "github.com/arafat-hasan/auth1/internal/telemetry"

// newMeterProvider returns a meter provider read by a Prometheus exporter on a registry of its
// own, never the global one, and the handler that serves that registry.
func newMeterProvider(res *resource.Resource) (*sdkmetric.MeterProvider, http.Handler, error) {
	reg := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		return nil, nil, fmt.Errorf("prometheus exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(exporter))
	return mp, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}), nil
}

// Metrics creates the TDD-08 §5.2 instruments on demand. It refuses a name outside the catalogue
// or of another kind, and returns the same instrument for the same name. It is safe for
// concurrent use.
type Metrics struct {
	meter metric.Meter

	mu          sync.Mutex
	instruments map[string]any
}

// NewMetrics returns a Metrics creating its instruments with mp.
func NewMetrics(mp metric.MeterProvider) *Metrics {
	return &Metrics{meter: mp.Meter(meterName), instruments: map[string]any{}}
}

// Counter returns the catalogue counter name.
func (m *Metrics) Counter(name string) (metric.Int64Counter, error) {
	return instrument(m, name, KindCounter, func() (metric.Int64Counter, error) {
		return m.meter.Int64Counter(name)
	})
}

// Gauge returns the catalogue gauge name.
func (m *Metrics) Gauge(name string) (metric.Float64Gauge, error) {
	return instrument(m, name, KindGauge, func() (metric.Float64Gauge, error) {
		return m.meter.Float64Gauge(name)
	})
}

// Histogram returns the catalogue histogram name.
func (m *Metrics) Histogram(name string) (metric.Float64Histogram, error) {
	return instrument(m, name, KindHistogram, func() (metric.Float64Histogram, error) {
		return m.meter.Float64Histogram(name)
	})
}

// instrument checks name against the catalogue and returns the cached instrument, creating it
// with create the first time.
func instrument[T any](m *Metrics, name string, kind Kind, create func() (T, error)) (T, error) {
	var zero T
	got, ok := catalogue[name]
	if !ok {
		return zero, fmt.Errorf("metric %q is not in the TDD-08 §5.2 catalogue", name)
	}
	if got != kind {
		return zero, fmt.Errorf("metric %q is a %s, not a %s", name, got, kind)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if inst, ok := m.instruments[name]; ok {
		return inst.(T), nil // name fixes the kind, so the type always matches
	}
	inst, err := create()
	if err != nil {
		return zero, fmt.Errorf("create metric %q: %w", name, err)
	}
	m.instruments[name] = inst
	return inst, nil
}
