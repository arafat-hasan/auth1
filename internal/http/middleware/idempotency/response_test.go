package idempotency

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/problem"
)

// TestRenderThenWrite: Write sends exactly what Render captured, so a replay is the first answer.
func TestRenderThenWrite(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		write func(w http.ResponseWriter) error
		want  app.IdempotentResponse
	}{
		{"json", func(w http.ResponseWriter) error {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Ignored", "1")
			w.WriteHeader(201)
			_, err := w.Write([]byte(`{"n":1}`))
			return err
		}, app.IdempotentResponse{Status: 201, ContentType: "application/json", Body: []byte(`{"n":1}`)}},
		{"no content", func(w http.ResponseWriter) error { w.WriteHeader(204); return nil },
			app.IdempotentResponse{Status: 204}},
		{"implicit 200", func(w http.ResponseWriter) error { _, err := w.Write([]byte("x")); return err },
			app.IdempotentResponse{Status: 200, Body: []byte("x")}},
	} {
		got, err := Render(tc.write)
		if err != nil {
			t.Fatalf("%s: Render: %v", tc.name, err)
		}
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("%s: Render (-want +got):\n%s", tc.name, diff)
		}
		rec := httptest.NewRecorder()
		if err := Write(rec, got); err != nil {
			t.Fatal(err)
		}
		if rec.Code != tc.want.Status || rec.Body.String() != string(tc.want.Body) ||
			rec.Header().Get("Content-Type") != tc.want.ContentType || rec.Header().Get("X-Ignored") != "" {
			t.Errorf("%s: Write sent %d %q %q", tc.name, rec.Code, rec.Header(), rec.Body)
		}
	}

	errVisit := errors.New("visit failed")
	if got, err := Render(func(http.ResponseWriter) error { return errVisit }); got.Status != 500 || !errors.Is(err, errVisit) {
		t.Errorf("Render of a failed write = %v, %v; want status 500 and the write's error", got, err)
	}
}

// TestRenderError: a domain error renders as its problem; any other error renders as a bare 503
// without logging, because Run returns that error and the handler writes and logs it once.
func TestRenderError(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	pw := problem.New(slog.New(slog.NewTextHandler(&logs, nil)))
	r := httptest.NewRequest(http.MethodPut, path, nil)

	got, err := RenderError(pw, r, &domain.Error{Code: domain.CodeStatusTransitionInvalid})
	if err != nil || got.Status != 409 || got.ContentType != problem.ContentType {
		t.Errorf("RenderError(domain) = %v, %v; want a 409 problem", got, err)
	}
	got, err = RenderError(pw, r, &http.MaxBytesError{Limit: 1})
	if err != nil || got.Status != 413 {
		t.Errorf("RenderError(MaxBytesError) = %v, %v; want 413", got, err)
	}
	got, err = RenderError(pw, r, errors.New("database gone"))
	if err != nil || got.Status != 503 || len(got.Body) != 0 {
		t.Errorf("RenderError(unexpected) = %v, %v; want a bare 503", got, err)
	}
	if logs.Len() != 0 {
		t.Errorf("RenderError logged: %s", logs.String())
	}
}
