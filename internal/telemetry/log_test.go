package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
