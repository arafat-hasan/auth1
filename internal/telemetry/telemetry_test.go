package telemetry

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/arafat-hasan/auth1/internal/config"
)

// newTest builds a Telemetry for a test, with output to stdout and spans to exporter, and shuts it
// down when the test ends.
func newTest(t *testing.T, stdout *bytes.Buffer, exporter *tracetest.InMemoryExporter) *Telemetry {
	t.Helper()
	cfg := config.Telemetry{ServiceName: "svc-test", MetricsListen: ":9090"}
	s := settings{stdout: stdout}
	if exporter != nil {
		s.spanExporter = exporter
	}
	tel, err := newTelemetry(context.Background(), cfg, BuildInfo{Version: "v-test"}, s)
	if err != nil {
		t.Fatalf("newTelemetry: %v", err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })
	return tel
}

// TestSpanExported is the done-when test of #5: a span reaches the exporter with the service
// name and version.
func TestSpanExported(t *testing.T) {
	t.Parallel()

	exporter := tracetest.NewInMemoryExporter()
	tel := newTest(t, &bytes.Buffer{}, exporter)
	_, span := tel.TracerProvider().Tracer("test").Start(context.Background(), "op")
	span.End()
	if err := tel.tp.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	got := spans[0]
	if got.Name != "op" {
		t.Errorf("name = %q, want op", got.Name)
	}
	if !got.SpanContext.IsSampled() {
		t.Error("span is not sampled")
	}
	attrs := map[string]string{}
	for _, kv := range got.Resource.Attributes() {
		attrs[string(kv.Key)] = kv.Value.String()
	}
	if attrs["service.name"] != "svc-test" || attrs["service.version"] != "v-test" {
		t.Errorf("resource = %v, want service.name=svc-test and service.version=v-test", attrs)
	}
}

func TestParentBasedSampling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		flags trace.TraceFlags
		want  bool
	}{
		{"sampled parent", trace.FlagsSampled, true},
		{"unsampled parent", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tel := newTest(t, &bytes.Buffer{}, tracetest.NewInMemoryExporter())
			parent := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}, TraceFlags: tt.flags, Remote: true,
			})
			ctx := trace.ContextWithRemoteSpanContext(context.Background(), parent)
			_, span := tel.TracerProvider().Tracer("test").Start(ctx, "child")
			defer span.End()
			if got := span.IsRecording(); got != tt.want {
				t.Errorf("IsRecording = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPropagatorContinuesTraceparent(t *testing.T) {
	t.Parallel()

	tel := newTest(t, &bytes.Buffer{}, tracetest.NewInMemoryExporter())
	carrier := propagation.MapCarrier{"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"}
	ctx := tel.Propagator().Extract(context.Background(), carrier)
	_, span := tel.TracerProvider().Tracer("test").Start(ctx, "op")
	defer span.End()
	if got := span.SpanContext().TraceID().String(); got != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("trace id = %s, want the traceparent's", got)
	}
}

func TestLoggerUsesBuildInfo(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	tel := newTest(t, &buf, nil)
	tel.Logger().InfoContext(context.Background(), "hello", slog.String("password", "hunter2"))
	got := logLines(t, &buf)
	if len(got) != 1 || got[0]["service"] != "svc-test" || got[0]["version"] != "v-test" {
		t.Errorf("log lines = %v, want one with service=svc-test and version=v-test", got)
	}
	if strings.Contains(buf.String(), "hunter2") {
		t.Errorf("logger does not redact: %s", buf.String())
	}
}

func TestNewWithoutEndpoint(t *testing.T) {
	t.Parallel()

	tel, err := New(context.Background(), config.Telemetry{ServiceName: "svc"}, BuildInfo{Version: "v"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := tel.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

// TestOTLPExportPath checks that otlp_endpoint is the collector's base URL: spans are posted to
// its /v1/traces.
func TestOTLPExportPath(t *testing.T) {
	t.Parallel()

	paths := make(chan string, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.Method + " " + r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	for _, endpoint := range []string{srv.URL, srv.URL + "/"} {
		tel, err := New(context.Background(), config.Telemetry{ServiceName: "svc", OTLPEndpoint: endpoint}, BuildInfo{Version: "v"})
		if err != nil {
			t.Fatalf("New(%q): %v", endpoint, err)
		}
		_, span := tel.TracerProvider().Tracer("test").Start(context.Background(), "op")
		span.End()
		if err := tel.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		select {
		case got := <-paths:
			if got != "POST /v1/traces" {
				t.Errorf("endpoint %q: collector got %q, want POST /v1/traces", endpoint, got)
			}
		default:
			t.Errorf("endpoint %q: collector got no request", endpoint)
		}
	}
}

// TestShutdownBounded checks that an unreachable collector cannot hold Shutdown past its context.
func TestShutdownBounded(t *testing.T) {
	t.Parallel()

	cfg := config.Telemetry{ServiceName: "svc", OTLPEndpoint: "http://127.0.0.1:1"}
	tel, err := New(context.Background(), cfg, BuildInfo{Version: "v"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, span := tel.TracerProvider().Tracer("test").Start(context.Background(), "op")
	span.End()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	_ = tel.Shutdown(ctx) // an export error is expected
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Shutdown took %v, want at most the context's 2s and some slack", d)
	}
}

// shutdownRecorder is a span exporter that records whether it was shut down.
type shutdownRecorder struct {
	*tracetest.InMemoryExporter
	shutDown bool
}

func (e *shutdownRecorder) Shutdown(ctx context.Context) error {
	e.shutDown = true
	return e.InMemoryExporter.Shutdown(ctx)
}

// TestFailedNewShutsExporterDown checks that the exporter New built is not left open when New
// fails after building it.
func TestFailedNewShutsExporterDown(t *testing.T) {
	t.Parallel()

	exp := &shutdownRecorder{InMemoryExporter: tracetest.NewInMemoryExporter()}
	_, err := newTelemetry(context.Background(), config.Telemetry{}, BuildInfo{}, settings{stdout: &bytes.Buffer{}, spanExporter: exp})
	if err == nil {
		t.Fatal("newTelemetry with an empty service name succeeded")
	}
	if !exp.shutDown {
		t.Error("span exporter was not shut down")
	}
}
