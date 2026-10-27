package telemetry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/arafat-hasan/auth1/internal/config"
)

// Telemetry holds the logger, the tracer and meter providers, and the metrics handler of one
// process. It sets no global state: the caller decides whether to install them as defaults.
type Telemetry struct {
	logger  *slog.Logger
	tp      *sdktrace.TracerProvider
	mp      *sdkmetric.MeterProvider
	metrics http.Handler
}

// settings are the outputs New would otherwise choose: stdout for logs, and the span exporter.
// Tests replace them.
type settings struct {
	stdout       io.Writer
	spanExporter sdktrace.SpanExporter // nil: spans are not exported
}

// New builds the logger (JSON on stdout), the tracer provider, which exports over OTLP/HTTP when
// cfg.OTLPEndpoint is set, and the meter provider, whose metrics MetricsHandler serves for
// Prometheus. Shutdown flushes and stops the providers.
func New(ctx context.Context, cfg config.Telemetry, info BuildInfo) (*Telemetry, error) {
	s := settings{stdout: os.Stdout}
	if cfg.OTLPEndpoint != "" {
		exp, err := newOTLPExporter(ctx, cfg.OTLPEndpoint)
		if err != nil {
			return nil, err
		}
		s.spanExporter = exp
	}
	return newTelemetry(ctx, cfg, info, s)
}

// newTelemetry builds the Telemetry from s. When it fails, it shuts s.spanExporter down, since no
// tracer provider owns it yet.
func newTelemetry(ctx context.Context, cfg config.Telemetry, info BuildInfo, s settings) (*Telemetry, error) {
	fail := func(err error) (*Telemetry, error) {
		if s.spanExporter != nil {
			if serr := s.spanExporter.Shutdown(ctx); serr != nil {
				err = errors.Join(err, fmt.Errorf("span exporter: %w", serr))
			}
		}
		return nil, err
	}
	if cfg.ServiceName == "" {
		return fail(fmt.Errorf("telemetry: empty service name"))
	}
	res := newResource(cfg.ServiceName, info.Version)
	mp, metrics, err := newMeterProvider(res)
	if err != nil {
		return fail(err)
	}
	return &Telemetry{
		logger:  slog.New(NewHandler(s.stdout, cfg.ServiceName, info.Version)),
		tp:      newTracerProvider(res, s.spanExporter),
		mp:      mp,
		metrics: metrics,
	}, nil
}

// Logger returns the redacting JSON logger.
func (t *Telemetry) Logger() *slog.Logger { return t.logger }

// TracerProvider returns the tracer provider.
func (t *Telemetry) TracerProvider() trace.TracerProvider { return t.tp }

// MeterProvider returns the meter provider. NewMetrics creates the catalogue instruments on it.
func (t *Telemetry) MeterProvider() metric.MeterProvider { return t.mp }

// MetricsHandler serves the metrics in the Prometheus text format. It belongs on the internal
// listener telemetry.metrics_listen, never on the public one.
func (t *Telemetry) MetricsHandler() http.Handler { return t.metrics }

// Propagator returns the W3C trace context propagator, which reads and writes traceparent.
func (t *Telemetry) Propagator() propagation.TextMapPropagator { return propagation.TraceContext{} }

// Shutdown flushes pending spans and stops the providers. It returns when ctx is done at the
// latest, with every error joined.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	var errs []error
	if err := t.tp.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("tracer provider: %w", err))
	}
	if err := t.mp.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("meter provider: %w", err))
	}
	return errors.Join(errs...)
}
