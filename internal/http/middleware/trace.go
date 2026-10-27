package middleware

import (
	"net/http"
	"strconv"

	chimw "github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// tracerName is the instrumentation scope of the server spans.
const tracerName = "github.com/arafat-hasan/auth1/internal/http/middleware"

// Trace starts one server span per request, continuing an incoming traceparent read with prop
// (TDD-08 §5.3). After routing it names the span "METHOD route" and sets the HTTP semantic-convention
// attributes. It records the route pattern, never the raw path, query or headers (G-6). It must be
// installed with chi.Router.Use so that the route pattern is known when the handler returns.
func Trace(tp trace.TracerProvider, prop propagation.TextMapPropagator) func(http.Handler) http.Handler {
	tracer := tp.Tracer(tracerName)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := prop.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			method := normalMethod(r.Method)
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			ctx, span := tracer.Start(ctx, spanName(method, ""),
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(semconv.HTTPRequestMethodKey.String(method), semconv.URLScheme(scheme)))

			ww := wrap(w, r)
			completed := false
			defer func() { endSpan(span, ww, r, method, !completed) }()
			next.ServeHTTP(ww, r.WithContext(ctx))
			completed = true
		})
	}
}

// endSpan names the span after routing, sets the response attributes and ends it. An aborted
// request is marked as an error with error.type=aborted.
func endSpan(span trace.Span, ww chimw.WrapResponseWriter, r *http.Request, method string, aborted bool) {
	defer span.End()
	code := responseStatus(ww, aborted)
	var attrs []attribute.KeyValue
	if code != 0 {
		attrs = append(attrs, semconv.HTTPResponseStatusCode(code))
	}
	route := routePattern(r)
	if route != "" {
		attrs = append(attrs, semconv.HTTPRoute(route))
	}
	switch {
	case aborted:
		attrs = append(attrs, semconv.ErrorTypeKey.String(abortedType))
		span.SetStatus(codes.Error, "")
	case code >= http.StatusInternalServerError:
		attrs = append(attrs, semconv.ErrorTypeKey.String(strconv.Itoa(code)))
		span.SetStatus(codes.Error, "")
	}
	span.SetAttributes(attrs...)
	span.SetName(spanName(method, route))
}

// spanName is "METHOD route", "METHOD" when no route matched, and "HTTP" for an unknown method.
func spanName(method, route string) string {
	if method == otherMethod {
		method = "HTTP"
	}
	if route == "" {
		return method
	}
	return method + " " + route
}
