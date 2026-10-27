package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arafat-hasan/auth1/internal/http/problem"
)

func TestBodyLimit(t *testing.T) {
	t.Parallel()

	const limit = 64 << 10
	tests := []struct {
		name        string
		size        int
		chunked     bool
		wantStatus  int
		wantReached bool
	}{
		{name: "at the limit", size: limit, wantStatus: 200, wantReached: true},
		{name: "declared over the limit", size: limit + 1, wantStatus: 413},
		{name: "chunked at the limit", size: limit, chunked: true, wantStatus: 200, wantReached: true},
		{name: "chunked over the limit", size: limit + 1, chunked: true, wantStatus: 413, wantReached: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pw := problem.New(slog.New(slog.NewJSONHandler(io.Discard, nil)))
			reached := false
			h := BodyLimit(limit, pw)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				if _, err := io.ReadAll(r.Body); err != nil {
					pw.Write(w, r, err)
				}
			}))
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("a", tt.size)))
			if tt.chunked {
				req.ContentLength = -1
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status %d, want %d", rec.Code, tt.wantStatus)
			}
			if reached != tt.wantReached {
				t.Errorf("handler reached %v, want %v", reached, tt.wantReached)
			}
			if tt.wantStatus == 413 {
				var body map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["code"] != "VALIDATION_FAILED" {
					t.Errorf("body %s", rec.Body)
				}
			}
		})
	}
}

func TestBodyLimitOverTheWire(t *testing.T) {
	t.Parallel()

	pw := problem.New(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	srv := httptest.NewServer(BodyLimit(64<<10, pw)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			pw.Write(w, r, err)
		}
	})))
	defer srv.Close()

	// A reader of unknown length is sent chunked.
	body := io.MultiReader(bytes.NewReader(make([]byte, 64<<10)), strings.NewReader("x"))
	resp, err := http.Post(srv.URL, "application/json", body) //nolint:noctx // test server
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", resp.StatusCode)
	}
}
