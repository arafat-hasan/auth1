package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"testing/slogtest"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.opentelemetry.io/otel/trace"
)

// logLines decodes each JSON line written to buf.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		lines = append(lines, m)
	}
	return lines
}

// logOne logs one record with f into a fresh handler and returns the decoded line.
func logOne(ctx context.Context, t *testing.T, f func(ctx context.Context, l *slog.Logger)) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	f(ctx, slog.New(NewHandler(&buf, "svc", "v1")))
	lines := logLines(t, &buf)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	return lines[0]
}

func TestHandlerFields(t *testing.T) {
	t.Parallel()

	got := logOne(context.Background(), t, func(ctx context.Context, l *slog.Logger) {
		l.InfoContext(ctx, "hello", RequestID("r1"), Err(errors.New("boom")))
	})
	ts, ok := got["ts"].(string)
	if !ok {
		t.Fatalf("ts = %v, want a string", got["ts"])
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("ts %q is not RFC 3339: %v", ts, err)
	}
	delete(got, "ts")
	want := map[string]any{
		"level": "INFO", "msg": "hello", "service": "svc", "version": "v1",
		"request_id": "r1", "error": "boom",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("record (-want +got):\n%s", diff)
	}
}

func TestHandlerTraceIDs(t *testing.T) {
	t.Parallel()

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x0a, 0xf7, 0x65, 0x19, 0x16, 0xcd, 0x43, 0xdd, 0x84, 0x48, 0xeb, 0x21, 0x1c, 0x80, 0x31, 0x9c},
		SpanID:     trace.SpanID{0xb7, 0xad, 0x6b, 0x71, 0x69, 0x20, 0x33, 0x31},
		TraceFlags: trace.FlagsSampled,
	})
	withSpan := trace.ContextWithSpanContext(context.Background(), sc)
	const traceID, spanID = "0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331"

	tests := []struct {
		name string
		ctx  context.Context
		log  func(ctx context.Context, l *slog.Logger)
		want map[string]any
	}{
		{
			name: "span",
			ctx:  withSpan,
			log:  func(ctx context.Context, l *slog.Logger) { l.InfoContext(ctx, "m") },
			want: map[string]any{"level": "INFO", "msg": "m", "service": "svc", "version": "v1",
				"trace_id": traceID, "span_id": spanID},
		},
		{
			name: "no span",
			ctx:  context.Background(),
			log:  func(ctx context.Context, l *slog.Logger) { l.InfoContext(ctx, "m") },
			want: map[string]any{"level": "INFO", "msg": "m", "service": "svc", "version": "v1"},
		},
		{
			name: "span inside a group",
			ctx:  withSpan,
			log: func(ctx context.Context, l *slog.Logger) {
				l.WithGroup("req").With("a", 1).InfoContext(ctx, "m", "b", 2)
			},
			want: map[string]any{"level": "INFO", "msg": "m", "service": "svc", "version": "v1",
				"trace_id": traceID, "span_id": spanID,
				"req": map[string]any{"a": float64(1), "b": float64(2)}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := logOne(tt.ctx, t, tt.log)
			delete(got, "ts")
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("record (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()

	got := logOne(context.Background(), t, func(ctx context.Context, l *slog.Logger) {
		l.InfoContext(ctx, "m", RequestID("r"), AccountID("a"), ClientID("c"), Caller("k"), Event("e"), Err(nil))
	})
	delete(got, "ts")
	want := map[string]any{"level": "INFO", "msg": "m", "service": "svc", "version": "v1",
		"request_id": "r", "account_id": "a", "client_id": "c", "caller": "k", "event": "e"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("record (-want +got):\n%s", diff)
	}
}

// TestHandlerConformance runs the standard library's handler checks, with ts read as time.
func TestHandlerConformance(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	newHandler := func(*testing.T) slog.Handler {
		buf.Reset()
		return NewHandler(&buf, "svc", "v1")
	}
	result := func(t *testing.T) map[string]any {
		lines := logLines(t, &buf)
		if len(lines) != 1 {
			t.Fatalf("got %d lines, want 1", len(lines))
		}
		m := lines[0]
		if ts, ok := m["ts"]; ok {
			m[slog.TimeKey] = ts
			delete(m, "ts")
		}
		return m
	}
	slogtest.Run(t, newHandler, result)
}

// TestUserTimeAttr checks that an attribute the caller names time keeps its name and does not
// become a second ts, which a JSON reader would take in place of the record's time.
func TestUserTimeAttr(t *testing.T) {
	t.Parallel()

	userTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	const userTS = "1970-01-01T00:00:00Z"
	withSpan := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}, TraceFlags: trace.FlagsSampled,
	}))

	tests := []struct {
		name string
		ctx  context.Context
		log  func(ctx context.Context, l *slog.Logger)
		want func(m map[string]any) any // where the caller's time ends up
	}{
		{
			name: "record attribute",
			ctx:  context.Background(),
			log:  func(ctx context.Context, l *slog.Logger) { l.InfoContext(ctx, "m", slog.Time("time", userTime)) },
			want: func(m map[string]any) any { return m["time"] },
		},
		{
			name: "record attribute with a span",
			ctx:  withSpan,
			log:  func(ctx context.Context, l *slog.Logger) { l.InfoContext(ctx, "m", slog.Time("time", userTime)) },
			want: func(m map[string]any) any { return m["time"] },
		},
		{
			name: "With attribute",
			ctx:  withSpan,
			log: func(ctx context.Context, l *slog.Logger) {
				l.With(slog.Time("time", userTime)).InfoContext(ctx, "m")
			},
			want: func(m map[string]any) any { return m["time"] },
		},
		{
			name: "inside a group",
			ctx:  context.Background(),
			log: func(ctx context.Context, l *slog.Logger) {
				l.WithGroup("g").InfoContext(ctx, "m", slog.Time("time", userTime))
			},
			want: func(m map[string]any) any { return m["g"].(map[string]any)["time"] },
		},
		{
			name: "group named time",
			ctx:  context.Background(),
			log: func(ctx context.Context, l *slog.Logger) {
				l.InfoContext(ctx, "m", slog.Group("time", slog.Time("at", userTime)))
			},
			want: func(m map[string]any) any { return m["time"].(map[string]any)["at"] },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			tt.log(tt.ctx, slog.New(NewHandler(&buf, "svc", "v1")))
			if n := strings.Count(buf.String(), `"ts":`); n != 1 {
				t.Fatalf("line has %d ts keys, want 1:\n%s", n, buf.String())
			}
			if strings.Contains(buf.String(), userTimeKey) {
				t.Fatalf("line holds the stand-in key:\n%s", buf.String())
			}
			m := logLines(t, &buf)[0]
			if m["ts"] == userTS {
				t.Errorf("ts is the caller's time, want the record's")
			}
			if got := tt.want(m); got != userTS {
				t.Errorf("caller's time = %v, want %s:\n%s", got, userTS, buf.String())
			}
		})
	}
}

// BenchmarkHandle measures a request-style logger, with attributes from With, with and without
// a span. With a span the handler rebuilds its chain for each record.
func BenchmarkHandle(b *testing.B) {
	withSpan := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}, TraceFlags: trace.FlagsSampled,
	}))
	l := slog.New(NewHandler(io.Discard, "svc", "v1")).
		With(RequestID("r1"), ClientID("c1")).WithGroup("req").With("method", "GET", "route", "/x")
	for _, bc := range []struct {
		name string
		ctx  context.Context
	}{{"no span", context.Background()}, {"span", withSpan}} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				l.InfoContext(bc.ctx, "request", "status", 200)
			}
		})
	}
}
