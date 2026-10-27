package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/arafat-hasan/auth1/internal/http/requestid"
	"github.com/arafat-hasan/auth1/internal/telemetry"
)

// logRouter returns the test router with the request id and access log middleware, logging to
// logs and recording to a manual reader.
func logRouter(t *testing.T, logs *bytes.Buffer) (http.Handler, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	hist, err := telemetry.NewMetrics(mp).Histogram("http.server.request.duration")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(telemetry.NewHandler(logs, "svc", "v"))
	return testRouter(requestid.Middleware, AccessLog(logger, hist)), reader
}

func TestAccessLog(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		method    string
		target    string
		upstream  string
		wantLevel string
		wantRoute string
		wantCode  float64
		wantBytes float64
		wantUp    string
	}{
		{name: "matched route", method: http.MethodGet, target: "/v1/things/secret-123?q=secret-q",
			wantLevel: "INFO", wantRoute: "/v1/things/{id}", wantCode: 200, wantBytes: 5},
		{name: "server error", method: http.MethodGet, target: "/fail",
			wantLevel: "ERROR", wantRoute: "/fail", wantCode: 503},
		{name: "unmatched", method: http.MethodGet, target: "/secret-path",
			wantLevel: "INFO", wantRoute: "", wantCode: 404, wantBytes: 19},
		{name: "upstream id", method: http.MethodGet, target: "/silent", upstream: "up-1",
			wantLevel: "INFO", wantRoute: "/silent", wantCode: 200, wantUp: "up-1"},
		{name: "unknown method", method: "FOO", target: "/silent",
			wantLevel: "INFO", wantRoute: "", wantCode: 405},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			h, _ := logRouter(t, &logs)
			req := httptest.NewRequest(tt.method, tt.target, strings.NewReader("secret-b"))
			req.Header.Set("Authorization", "Bearer secret-a")
			if tt.upstream != "" {
				req.Header.Set(requestid.Header, tt.upstream)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if strings.Contains(logs.String(), "secret") {
				t.Errorf("log leaks the request: %s", logs.String())
			}
			lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
			if len(lines) != 1 {
				t.Fatalf("%d log lines, want 1: %s", len(lines), logs.String())
			}
			var line map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
				t.Fatal(err)
			}
			wantMethod := tt.method
			if wantMethod == "FOO" {
				wantMethod = "_OTHER"
			}
			checks := map[string]any{
				"level": tt.wantLevel, "msg": "request", "method": wantMethod, "route": tt.wantRoute,
				"status": tt.wantCode, "request_id": rec.Header().Get(requestid.Header),
			}
			for k, want := range checks {
				if line[k] != want {
					t.Errorf("%s = %v, want %v", k, line[k], want)
				}
			}
			if tt.wantBytes != 0 && line["bytes"] != tt.wantBytes {
				t.Errorf("bytes = %v, want %v", line["bytes"], tt.wantBytes)
			}
			if d, ok := line["duration"].(float64); !ok || d <= 0 {
				t.Errorf("duration = %v, want seconds > 0", line["duration"])
			}
			if up, _ := line["upstream_request_id"].(string); up != tt.wantUp {
				t.Errorf("upstream_request_id = %q, want %q", up, tt.wantUp)
			}
		})
	}
}

func TestAccessLogAborted(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	h, reader := logRouter(t, &logs)
	serveAborting(t, h)

	var line map[string]any
	if err := json.Unmarshal(logs.Bytes(), &line); err != nil {
		t.Fatalf("log is not one JSON line: %v: %s", err, logs.String())
	}
	want := map[string]any{"level": "ERROR", "msg": "request", "route": "/abort", "status": 0.0, "aborted": true}
	for k, v := range want {
		if line[k] != v {
			t.Errorf("%s = %v, want %v", k, line[k], v)
		}
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	wantSet := attribute.NewSet(attribute.String("http.request.method", "GET"),
		attribute.String("http.route", "/abort"), attribute.String("error.type", "aborted"))
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			for _, dp := range m.Data.(metricdata.Histogram[float64]).DataPoints {
				if dp.Attributes.Equals(&wantSet) && dp.Count == 1 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("no data point with %s", wantSet.Encoded(attribute.DefaultEncoder()))
	}
}

func TestRequestDurationMetric(t *testing.T) {
	t.Parallel()

	h, reader := logRouter(t, &bytes.Buffer{})
	for _, target := range []string{"/v1/things/1", "/v1/things/2", "/nope"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("FOO", "/silent", nil))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	got := map[attribute.Distinct]uint64{}
	sets := map[attribute.Distinct]attribute.Set{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "http.server.request.duration" {
				continue
			}
			if m.Unit != "s" {
				t.Errorf("unit %q, want s", m.Unit)
			}
			for _, dp := range m.Data.(metricdata.Histogram[float64]).DataPoints {
				got[dp.Attributes.Equivalent()] = dp.Count
				sets[dp.Attributes.Equivalent()] = dp.Attributes
			}
		}
	}
	want := map[attribute.Set]uint64{
		attribute.NewSet(attribute.String("http.request.method", "GET"), attribute.String("http.route", "/v1/things/{id}"),
			attribute.Int("http.response.status_code", 200)): 2,
		attribute.NewSet(attribute.String("http.request.method", "GET"), attribute.Int("http.response.status_code", 404)):    1,
		attribute.NewSet(attribute.String("http.request.method", "_OTHER"), attribute.Int("http.response.status_code", 405)): 1,
	}
	if len(got) != len(want) {
		var all []string
		for _, s := range sets {
			all = append(all, s.Encoded(attribute.DefaultEncoder()))
		}
		t.Errorf("%d series, want %d: %v", len(got), len(want), all)
	}
	for set, n := range want {
		if got[set.Equivalent()] != n {
			t.Errorf("series %s count %d, want %d", set.Encoded(attribute.DefaultEncoder()), got[set.Equivalent()], n)
		}
	}
}
