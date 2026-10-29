package problem

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/requestid"
)

// write renders err through a Writer logging to logs, inside the request id middleware.
func write(t *testing.T, logs *bytes.Buffer, err error) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	pw := New(slog.New(slog.NewJSONHandler(logs, nil)))
	h := requestid.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pw.Write(w, r, err)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, rec.Body)
	}
	return rec, body
}

func TestEveryCodeRenders(t *testing.T) {
	t.Parallel()

	// SDD §10.
	want := map[domain.Code]int{
		domain.CodeValidationFailed:         422,
		domain.CodeIdentifierNotAllowed:     422,
		domain.CodePasswordRejected:         422,
		domain.CodeIdentifierTaken:          409,
		domain.CodeVerificationIncomplete:   409,
		domain.CodeCodeInvalid:              400,
		domain.CodeChallengeClosed:          410,
		domain.CodeResendTooSoon:            429,
		domain.CodeInvalidCredentials:       401,
		domain.CodeSignInDelayed:            429,
		domain.CodeRegistrationIncomplete:   403,
		domain.CodeRoleNotPermitted:         403,
		domain.CodeAccountRestricted:        403,
		domain.CodeSessionInvalid:           401,
		domain.CodeTokenInvalid:             401,
		domain.CodeReauthenticationRequired: 403,
		domain.CodeCallerNotAllowed:         403,
		domain.CodeIdempotencyKeyReused:     422,
		domain.CodeStatusTransitionInvalid:  409,
		domain.CodeMFAStateInvalid:          409,
		domain.CodeRoleUnknown:              422,
		domain.CodeNotFound:                 404,
		domain.CodeRateLimited:              429,
		domain.CodeUnavailable:              503,
	}
	if diff := cmp.Diff(slices.Sorted(maps.Keys(want)), slices.Sorted(slices.Values(domain.Codes()))); diff != "" {
		t.Fatalf("test table does not cover the catalogue (-test +catalogue):\n%s", diff)
	}

	for _, code := range domain.Codes() {
		t.Run(string(code), func(t *testing.T) {
			t.Parallel()
			status, ok := Status(code)
			if !ok || status != want[code] {
				t.Errorf("Status(%s) = %d, %v; want %d", code, status, ok, want[code])
			}

			rec, body := write(t, &bytes.Buffer{}, &domain.Error{Code: code, Detail: "d"})
			if rec.Code != want[code] {
				t.Errorf("status %d, want %d", rec.Code, want[code])
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("Content-Type %q", ct)
			}
			wantBody := map[string]any{
				"type":   "about:blank",
				"title":  http.StatusText(want[code]),
				"status": float64(want[code]),
				"code":   string(code),
				"detail": "d",
			}
			if diff := cmp.Diff(wantBody, body); diff != "" {
				t.Errorf("body (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStatusUnknownCode(t *testing.T) {
	t.Parallel()

	if _, ok := Status("NOPE"); ok {
		t.Error("Status accepted a code outside the catalogue")
	}
}

func TestOptionalMembers(t *testing.T) {
	t.Parallel()

	zero := 0
	tests := []struct {
		name       string
		err        *domain.Error
		wantBody   map[string]any // members beyond type, title, status, code
		wantHeader string         // Retry-After
	}{
		{name: "none", err: &domain.Error{Code: domain.CodeNotFound}, wantBody: map[string]any{}},
		{name: "retry after rounds up", err: &domain.Error{Code: domain.CodeRateLimited, RetryAfter: 1500 * time.Millisecond},
			wantBody: map[string]any{"retry_after": float64(2)}, wantHeader: "2"},
		{name: "retry after at least one", err: &domain.Error{Code: domain.CodeUnavailable, RetryAfter: 200 * time.Millisecond},
			wantBody: map[string]any{"retry_after": float64(1)}, wantHeader: "1"},
		{name: "retry after whole", err: &domain.Error{Code: domain.CodeSignInDelayed, RetryAfter: 30 * time.Second},
			wantBody: map[string]any{"retry_after": float64(30)}, wantHeader: "30"},
		{name: "attempts left zero", err: &domain.Error{Code: domain.CodeCodeInvalid, AttemptsLeft: &zero},
			wantBody: map[string]any{"attempts_left": float64(0)}},
		{name: "reasons", err: &domain.Error{Code: domain.CodePasswordRejected, Reasons: []string{"too_short", "common"}},
			wantBody: map[string]any{"reasons": []any{"too_short", "common"}}},
		{name: "field errors", err: &domain.Error{Code: domain.CodeValidationFailed,
			Fields: []domain.FieldError{{Field: "locale", Code: "pattern"}}},
			wantBody: map[string]any{"errors": []any{map[string]any{"field": "locale", "code": "pattern"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec, body := write(t, &bytes.Buffer{}, tt.err)
			for _, k := range []string{"type", "title", "status", "code"} {
				delete(body, k)
			}
			if diff := cmp.Diff(tt.wantBody, body); diff != "" {
				t.Errorf("optional members (-want +got):\n%s", diff)
			}
			if got := rec.Header().Get("Retry-After"); got != tt.wantHeader {
				t.Errorf("Retry-After %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

func TestNonDomainError(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	rec, body := write(t, &logs, fmt.Errorf("query: %w", errors.New("db: secret-cause")))
	if rec.Code != http.StatusServiceUnavailable || body["code"] != "UNAVAILABLE" {
		t.Errorf("got %d %v", rec.Code, body["code"])
	}
	if body["detail"] != "The service is temporarily unavailable." {
		t.Errorf("detail %q", body["detail"])
	}
	if _, ok := body["retry_after"]; ok || rec.Header().Get("Retry-After") != "" {
		t.Error("an unexpected failure carries a retry hint")
	}
	if strings.Contains(rec.Body.String(), "secret-cause") {
		t.Error("the cause reached the response")
	}

	var line map[string]any
	if err := json.Unmarshal(logs.Bytes(), &line); err != nil {
		t.Fatalf("log is not one JSON line: %v: %s", err, logs.String())
	}
	if line["level"] != "ERROR" || line["error"] != "query: db: secret-cause" {
		t.Errorf("log line %v", line)
	}
	if line["request_id"] != rec.Header().Get(requestid.Header) || line["request_id"] == "" {
		t.Errorf("log request_id %v, response %q", line["request_id"], rec.Header().Get(requestid.Header))
	}
}

func TestDomainErrorNotLogged(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	write(t, &logs, &domain.Error{Code: domain.CodeNotFound})
	if logs.Len() != 0 {
		t.Errorf("a domain error was logged: %s", logs.String())
	}
}

func TestBodyTooLarge(t *testing.T) {
	t.Parallel()

	rec, body := write(t, &bytes.Buffer{}, fmt.Errorf("decode: %w", &http.MaxBytesError{Limit: 65536}))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d", rec.Code)
	}
	want := map[string]any{
		"type":   "about:blank",
		"title":  "Request Entity Too Large",
		"status": float64(413),
		"code":   "VALIDATION_FAILED",
		"detail": "The request body exceeds 65536 bytes.",
	}
	if diff := cmp.Diff(want, body); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}
}

func TestUnknownDomainCode(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	rec, body := write(t, &logs, &domain.Error{Code: "NOPE", Detail: "d"})
	if rec.Code != http.StatusServiceUnavailable || body["code"] != "UNAVAILABLE" || body["detail"] == "d" {
		t.Errorf("got %d %v %v", rec.Code, body["code"], body["detail"])
	}
	if !strings.Contains(logs.String(), `unknown error code \"NOPE\"`) {
		t.Errorf("not logged: %s", logs.String())
	}
}

// TestWriteNotImplemented checks the 501 of an operation with no handler yet: a problem with no
// code, because the SDD §10 catalogue has none for it.
func TestWriteNotImplemented(t *testing.T) {
	t.Parallel()

	pw := New(slog.New(slog.DiscardHandler))
	rec := httptest.NewRecorder()
	pw.WriteNotImplemented(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status %d, want 501", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != ContentType {
		t.Errorf("Content-Type %q, want %q", got, ContentType)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, rec.Body)
	}
	want := map[string]any{"type": "about:blank", "title": "Not Implemented", "status": float64(501)}
	if diff := cmp.Diff(want, body); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}
}
