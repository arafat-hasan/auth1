package idempotency

import (
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
	pw := problem.New(slog.New(slog.DiscardHandler))
	r := httptest.NewRequest(http.MethodPut, path, nil)

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
		got := Render(tc.write)
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

	if got := Render(func(http.ResponseWriter) error { return errors.New("visit failed") }); got.Status != 500 {
		t.Errorf("Render of a failed write = %v, want status 500", got)
	}

	got := RenderError(pw, r, &domain.Error{Code: domain.CodeStatusTransitionInvalid})
	if got.Status != 409 || got.ContentType != problem.ContentType {
		t.Errorf("RenderError = %v, want a 409 problem", got)
	}
}
