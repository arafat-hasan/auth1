package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type probeBody struct {
	Status string `json:"status"`
	Checks []struct {
		Name     string `json:"name"`
		Critical bool   `json:"critical"`
		Status   string `json:"status"`
	} `json:"checks"`
}

func get(t *testing.T, h http.Handler) (*httptest.ResponseRecorder, probeBody) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var b probeBody
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
	return rec, b
}

func ok(context.Context) error   { return nil }
func fail(context.Context) error { return errors.New("secret-err") }

func TestLive(t *testing.T) {
	t.Parallel()

	c := New(slog.New(slog.DiscardHandler))
	c.Register("down", fail, true)
	rec, b := get(t, c.Live())
	if rec.Code != http.StatusOK || b.Status != "ok" || b.Checks != nil {
		t.Errorf("got %d %+v", rec.Code, b)
	}
}

func TestReady(t *testing.T) {
	t.Parallel()

	type check struct {
		name     string
		fn       func(context.Context) error
		critical bool
	}
	type result struct{ name, status string }
	tests := []struct {
		name       string
		checks     []check
		wantCode   int
		wantStatus string
		want       []result
	}{
		{name: "no checks", wantCode: 200, wantStatus: "ready", want: []result{}},
		{name: "all pass", checks: []check{{"a", ok, true}, {"b", ok, false}},
			wantCode: 200, wantStatus: "ready", want: []result{{"a", "ok"}, {"b", "ok"}}},
		{name: "critical fails", checks: []check{{"a", ok, true}, {"db", fail, true}},
			wantCode: 503, wantStatus: "not_ready", want: []result{{"a", "ok"}, {"db", "failing"}}},
		{name: "only non-critical fails", checks: []check{{"a", ok, true}, {"redis", fail, false}},
			wantCode: 200, wantStatus: "ready", want: []result{{"a", "ok"}, {"redis", "failing"}}},
		{name: "registered again", checks: []check{{"a", fail, true}, {"b", ok, true}, {"a", ok, true}},
			wantCode: 200, wantStatus: "ready", want: []result{{"a", "ok"}, {"b", "ok"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			c := New(slog.New(slog.NewJSONHandler(&logs, nil)))
			for _, ch := range tt.checks {
				c.Register(ch.name, ch.fn, ch.critical)
			}
			rec, b := get(t, c.Ready())
			if rec.Code != tt.wantCode || b.Status != tt.wantStatus {
				t.Errorf("got %d %q, want %d %q", rec.Code, b.Status, tt.wantCode, tt.wantStatus)
			}
			got := []result{}
			for _, ch := range b.Checks {
				got = append(got, result{ch.Name, ch.Status})
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(result{})); diff != "" {
				t.Errorf("checks (-want +got):\n%s", diff)
			}
			if strings.Contains(rec.Body.String(), "secret-err") {
				t.Error("the error text reached the response")
			}
			failing := strings.Contains(rec.Body.String(), "failing")
			if failing != strings.Contains(logs.String(), "secret-err") {
				t.Errorf("failing check logged = %v, want %v: %s", !failing, failing, logs.String())
			}
		})
	}
}

func TestReadyCritical(t *testing.T) {
	t.Parallel()

	c := New(slog.New(slog.DiscardHandler))
	c.Register("db", ok, true)
	c.Register("redis", ok, false)
	_, b := get(t, c.Ready())
	if len(b.Checks) != 2 || !b.Checks[0].Critical || b.Checks[1].Critical {
		t.Errorf("critical flags %+v", b.Checks)
	}
}

func TestReadyTimeout(t *testing.T) {
	t.Parallel()

	c := New(slog.New(slog.DiscardHandler))
	c.timeout = 50 * time.Millisecond
	c.Register("slow", func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}, true)
	start := time.Now()
	rec, b := get(t, c.Ready())
	if rec.Code != http.StatusServiceUnavailable || b.Checks[0].Status != "failing" {
		t.Errorf("got %d %+v", rec.Code, b)
	}
	if time.Since(start) > time.Second {
		t.Error("the check was not bounded by the timeout")
	}
}

func TestReadyAbandonsStuckCheck(t *testing.T) {
	t.Parallel()

	c := New(slog.New(slog.DiscardHandler))
	c.timeout = 50 * time.Millisecond
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c.Register("stuck", func(context.Context) error { // ignores its context
		<-release
		return nil
	}, true)
	start := time.Now()
	rec, b := get(t, c.Ready())
	if rec.Code != http.StatusServiceUnavailable || b.Checks[0].Status != "failing" {
		t.Errorf("got %d %+v", rec.Code, b)
	}
	if time.Since(start) > time.Second {
		t.Error("a check that ignores its context held /readyz past the timeout")
	}
}

func TestDefaultTimeout(t *testing.T) {
	t.Parallel()

	if got := New(slog.New(slog.DiscardHandler)).timeout; got != 2*time.Second {
		t.Errorf("timeout %v, want 2s", got)
	}
}
