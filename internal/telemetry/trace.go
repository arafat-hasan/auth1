package telemetry

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// newResource describes this service: service.name and service.version only. It is not merged
// with resource.Default, so OTEL_* environment variables cannot add attributes.
func newResource(service, version string) *resource.Resource {
	return resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName(service),
		semconv.ServiceVersion(version),
	)
}

// tracesPath is where an OTLP/HTTP collector receives spans, under its base URL.
const tracesPath = "/v1/traces"

// newOTLPExporter returns an OTLP over HTTP span exporter posting to tracesPath under endpoint,
// the collector's base http or https URL. It does not connect until the first export.
func newOTLPExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(strings.TrimSuffix(endpoint, "/")+tracesPath))
	if err != nil {
		return nil, fmt.Errorf("otlp trace exporter: %w", err)
	}
	return exp, nil
}

// newTracerProvider samples every root span and follows the parent's decision otherwise
// (TDD-08 §5.3). Spans go to exporter through a batch processor; with no exporter they are
// recorded and dropped.
func newTracerProvider(res *resource.Resource, exporter sdktrace.SpanExporter) *sdktrace.TracerProvider {
	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
	}
	if exporter != nil {
		opts = append(opts, sdktrace.WithBatcher(exporter))
	}
	return sdktrace.NewTracerProvider(opts...)
}
