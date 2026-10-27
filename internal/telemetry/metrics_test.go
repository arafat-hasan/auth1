package telemetry

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// scrape GETs the metrics handler and returns the exposition text.
func scrape(t *testing.T, tel *Telemetry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	tel.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, body:\n%s", rec.Code, rec.Body)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// sampleLines returns the exposition lines of metric family name, comments excluded.
func sampleLines(body, name string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name+"{") || strings.HasPrefix(line, name+" ") {
			out = append(out, line)
		}
	}
	return out
}

func TestMetricsHandlerScrape(t *testing.T) {
	t.Parallel()

	tel := newTest(t, &bytes.Buffer{}, nil)
	c, err := NewMetrics(tel.MeterProvider()).Counter("auth1_rate_limited_total")
	if err != nil {
		t.Fatalf("Counter: %v", err)
	}
	c.Add(context.Background(), 1, metric.WithAttributes(attribute.String("rule", "test")))

	lines := sampleLines(scrape(t, tel), "auth1_rate_limited_total")
	if len(lines) != 1 || !strings.Contains(lines[0], `rule="test"`) || !strings.HasSuffix(lines[0], " 1") {
		t.Errorf("auth1_rate_limited_total samples = %q, want one with rule=\"test\" and value 1", lines)
	}
}

// TestEveryCatalogueNameScrapes creates every instrument of the catalogue and checks that each
// is exposed under its catalogue name, so the exporter's suffixing cannot rename one.
func TestEveryCatalogueNameScrapes(t *testing.T) {
	t.Parallel()

	tel := newTest(t, &bytes.Buffer{}, nil)
	m := NewMetrics(tel.MeterProvider())
	ctx := context.Background()
	for _, name := range InstrumentNames() {
		var err error
		switch catalogue[name] {
		case KindCounter:
			var c metric.Int64Counter
			if c, err = m.Counter(name); err == nil {
				c.Add(ctx, 1)
			}
		case KindGauge:
			var g metric.Float64Gauge
			if g, err = m.Gauge(name); err == nil {
				g.Record(ctx, 1)
			}
		case KindHistogram:
			var h metric.Float64Histogram
			if h, err = m.Histogram(name); err == nil {
				h.Record(ctx, 0.1)
			}
		}
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	body := scrape(t, tel)
	for _, name := range InstrumentNames() {
		family := name
		if catalogue[name] == KindHistogram {
			family = name + "_bucket"
		}
		if len(sampleLines(body, family)) == 0 {
			t.Errorf("no samples for %s in:\n%s", family, body)
		}
	}
}

func TestMetricsRefuses(t *testing.T) {
	t.Parallel()

	m := NewMetrics(newTest(t, &bytes.Buffer{}, nil).MeterProvider())
	tests := []struct {
		name   string
		create func() error
	}{
		{"unknown counter", func() error { _, err := m.Counter("auth1_unknown_total"); return err }},
		{"unknown gauge", func() error { _, err := m.Gauge("other_gauge"); return err }},
		{"unknown histogram", func() error { _, err := m.Histogram("auth1_unknown_seconds"); return err }},
		{"counter as gauge", func() error { _, err := m.Gauge("auth1_refresh_total"); return err }},
		{"gauge as counter", func() error { _, err := m.Counter("auth1_outbox_parked"); return err }},
		{"gauge as histogram", func() error { _, err := m.Histogram("auth1_jwks_keys"); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.create(); err == nil {
				t.Error("created an instrument outside the catalogue or of the wrong kind")
			}
		})
	}
}

func TestMetricsCachesInstruments(t *testing.T) {
	t.Parallel()

	tel := newTest(t, &bytes.Buffer{}, nil)
	m := NewMetrics(tel.MeterProvider())
	for range 2 {
		c, err := m.Counter("auth1_hash_rejected_total")
		if err != nil {
			t.Fatalf("Counter: %v", err)
		}
		c.Add(context.Background(), 1)
	}
	lines := sampleLines(scrape(t, tel), "auth1_hash_rejected_total")
	if len(lines) != 1 || !strings.HasSuffix(lines[0], " 2") {
		t.Errorf("auth1_hash_rejected_total samples = %q, want one with value 2", lines)
	}
}

func TestShutdownStopsMetrics(t *testing.T) {
	t.Parallel()

	tel := newTest(t, &bytes.Buffer{}, nil)
	if err := tel.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := tel.mp.Shutdown(context.Background()); err == nil {
		t.Error("meter provider still running after Shutdown")
	}
}
