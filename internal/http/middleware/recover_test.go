package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arafat-hasan/auth1/internal/http/problem"
)

func TestRecover(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantStatus int
		wantBody   string // exact body; empty means a problem body with UNAVAILABLE
		wantPanic  string
	}{
		{name: "string panic", handler: func(http.ResponseWriter, *http.Request) { panic("boom secret-p") },
			wantStatus: 503, wantPanic: "string"},
		{name: "error panic", handler: func(http.ResponseWriter, *http.Request) { panic(errors.New("e")) },
			wantStatus: 503, wantPanic: "e"},
		{name: "runtime error", handler: func(http.ResponseWriter, *http.Request) {
			var m map[string]int
			m["x"] = 1
		}, wantStatus: 503, wantPanic: "assignment to entry in nil map"},
		{name: "after the response started", handler: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
			panic("late")
		}, wantStatus: 200, wantBody: "ok", wantPanic: "string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			h := Recover(logger, problem.New(logger))(tt.handler)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" {
				if rec.Body.String() != tt.wantBody {
					t.Errorf("body %q, want %q", rec.Body.String(), tt.wantBody)
				}
			} else {
				var body map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["code"] != "UNAVAILABLE" {
					t.Errorf("body %s is not an UNAVAILABLE problem", rec.Body)
				}
				if rec.Header().Get("Retry-After") != "" {
					t.Error("a panic answers with a retry hint")
				}
			}

			var line map[string]any
			if err := json.Unmarshal(logs.Bytes(), &line); err != nil {
				t.Fatalf("log is not one JSON line: %v: %s", err, logs.String())
			}
			if line["level"] != "ERROR" || line["panic"] != tt.wantPanic {
				t.Errorf("log level %v panic %v, want ERROR %q", line["level"], line["panic"], tt.wantPanic)
			}
			if s, _ := line["stack"].(string); !strings.Contains(s, "goroutine") {
				t.Errorf("stack %q", s)
			}
			if strings.Contains(logs.String(), "secret") {
				t.Errorf("log leaks the panic value: %s", logs.String())
			}
		})
	}
}

func TestRecoverAbortHandler(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h := Recover(logger, problem.New(logger))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		if v := recover(); v != http.ErrAbortHandler { //nolint:errorlint // the exact sentinel is re-panicked
			t.Errorf("recovered %v, want http.ErrAbortHandler", v)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	t.Error("ErrAbortHandler did not propagate")
}
