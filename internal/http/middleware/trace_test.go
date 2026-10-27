package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// testRouter returns a Chi router with mws installed and the routes the middleware tests use.
func testRouter(mws ...func(http.Handler) http.Handler) chi.Router {
	r := chi.NewRouter()
	r.Use(mws...)
	r.Get("/v1/things/{id}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("thing"))
	})
	r.Get("/fail", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	r.Get("/silent", func(http.ResponseWriter, *http.Request) {})
	return r
}

const traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestTraceSpan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		target     string
		wantName   string
		wantAttrs  map[attribute.Key]attribute.Value
		wantStatus codes.Code
	}{
		{
			name: "matched route", method: http.MethodGet, target: "/v1/things/secret-123?q=secret-q",
			wantName: "GET /v1/things/{id}",
			wantAttrs: map[attribute.Key]attribute.Value{
				"http.request.method":       attribute.StringValue("GET"),
				"http.route":                attribute.StringValue("/v1/things/{id}"),
				"http.response.status_code": attribute.IntValue(200),
				"url.scheme":                attribute.StringValue("http"),
			},
		},
		{
			name: "unmatched path", method: http.MethodGet, target: "/secret-path",
			wantName: "GET",
			wantAttrs: map[attribute.Key]attribute.Value{
				"http.request.method":       attribute.StringValue("GET"),
				"http.response.status_code": attribute.IntValue(404),
				"url.scheme":                attribute.StringValue("http"),
			},
		},
		{
			name: "unknown method", method: "FOO", target: "/v1/things/1",
			wantName: "HTTP",
			wantAttrs: map[attribute.Key]attribute.Value{
				"http.request.method":       attribute.StringValue("_OTHER"),
				"http.response.status_code": attribute.IntValue(405),
				"url.scheme":                attribute.StringValue("http"),
			},
		},
		{
			name: "server error", method: http.MethodGet, target: "/fail",
			wantName: "GET /fail",
			wantAttrs: map[attribute.Key]attribute.Value{
				"http.request.method":       attribute.StringValue("GET"),
				"http.route":                attribute.StringValue("/fail"),
				"http.response.status_code": attribute.IntValue(503),
				"url.scheme":                attribute.StringValue("http"),
				"error.type":                attribute.StringValue("503"),
			},
			wantStatus: codes.Error,
		},
		{
			name: "handler writes nothing", method: http.MethodGet, target: "/silent",
			wantName: "GET /silent",
			wantAttrs: map[attribute.Key]attribute.Value{
				"http.request.method":       attribute.StringValue("GET"),
				"http.route":                attribute.StringValue("/silent"),
				"http.response.status_code": attribute.IntValue(200),
				"url.scheme":                attribute.StringValue("http"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := tracetest.NewSpanRecorder()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
			h := testRouter(Trace(tp, propagation.TraceContext{}))

			req := httptest.NewRequest(tt.method, tt.target, nil)
			req.Header.Set("traceparent", traceparent)
			req.Header.Set("Authorization", "Bearer secret-a")
			h.ServeHTTP(httptest.NewRecorder(), req)

			spans := rec.Ended()
			if len(spans) != 1 {
				t.Fatalf("%d spans, want 1", len(spans))
			}
			s := spans[0]
			if s.Name() != tt.wantName {
				t.Errorf("name %q, want %q", s.Name(), tt.wantName)
			}
			if s.SpanKind() != trace.SpanKindServer {
				t.Errorf("kind %v", s.SpanKind())
			}
			if got := s.SpanContext().TraceID().String(); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
				t.Errorf("trace id %s does not continue traceparent", got)
			}
			if s.Status().Code != tt.wantStatus {
				t.Errorf("status %v, want %v", s.Status().Code, tt.wantStatus)
			}
			got := map[attribute.Key]attribute.Value{}
			for _, kv := range s.Attributes() {
				got[kv.Key] = kv.Value
				if strings.Contains(kv.Value.String(), "secret") {
					t.Errorf("attribute %s = %q leaks the request", kv.Key, kv.Value.String())
				}
			}
			if len(got) != len(tt.wantAttrs) {
				t.Errorf("attributes %v, want %v", got, tt.wantAttrs)
			}
			for k, v := range tt.wantAttrs {
				if got[k] != v {
					t.Errorf("attribute %s = %v, want %v", k, got[k].String(), v.String())
				}
			}
		})
	}
}

func TestTraceContextReachesHandler(t *testing.T) {
	t.Parallel()

	tp := sdktrace.NewTracerProvider()
	var inside trace.SpanContext
	r := chi.NewRouter()
	r.Use(Trace(tp, propagation.TraceContext{}))
	r.Get("/", func(_ http.ResponseWriter, r *http.Request) {
		inside = trace.SpanContextFromContext(r.Context())
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !inside.IsValid() {
		t.Error("the handler's context has no span")
	}
}
