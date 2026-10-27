package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"github.com/arafat-hasan/auth1/internal/http/requestid"
	"github.com/arafat-hasan/auth1/internal/telemetry"
)

// AccessLog writes one line per request to logger, at info or at error for a 5xx, and records the
// request's duration on duration, the http.server.request.duration histogram (TDD-08 §5.1, §5.2).
// The line holds the method, the route pattern (empty when no route matched), the status, the
// duration in seconds, the bytes written and the request ids; never the raw path, query, headers
// or body (G-6). It must be installed with chi.Router.Use, after requestid.Middleware.
func AccessLog(logger *slog.Logger, duration metric.Float64Histogram) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := wrap(w, r)
			next.ServeHTTP(ww, r)
			elapsed := time.Since(start)

			method := normalMethod(r.Method)
			route := routePattern(r)
			code := status(ww)

			labels := []attribute.KeyValue{semconv.HTTPRequestMethodKey.String(method), semconv.HTTPResponseStatusCode(code)}
			if route != "" {
				labels = append(labels, semconv.HTTPRoute(route))
			}
			duration.Record(r.Context(), elapsed.Seconds(), metric.WithAttributes(labels...))

			level := slog.LevelInfo
			if code >= http.StatusInternalServerError {
				level = slog.LevelError
			}
			attrs := []slog.Attr{
				slog.String("method", method),
				slog.String("route", route),
				slog.Int("status", code),
				slog.Float64("duration", elapsed.Seconds()),
				slog.Int("bytes", ww.BytesWritten()),
				telemetry.RequestID(requestid.From(r.Context())),
			}
			if up := requestid.UpstreamFrom(r.Context()); up != "" {
				attrs = append(attrs, slog.String("upstream_request_id", up))
			}
			logger.LogAttrs(r.Context(), level, "request", attrs...)
		})
	}
}
