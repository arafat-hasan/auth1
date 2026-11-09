package idempotency

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/http/middleware"
	"github.com/arafat-hasan/auth1/internal/http/middleware/caller"
	"github.com/arafat-hasan/auth1/internal/http/problem"
)

const path = "/v1/accounts/0190a0a0-0000-7000-8000-000000000001/status"

// seen is what the next handler saw.
type seen struct {
	called bool
	req    app.IdempotencyRequest
	ok     bool
	body   string
}

// serve runs req through BodyLimit(64 KiB) and the middleware, matching every request when
// matched, with c as the caller (none when c is nil).
func serve(t *testing.T, matched bool, c *caller.Caller, req *http.Request) (*httptest.ResponseRecorder, *seen) {
	t.Helper()
	pw := problem.New(slog.New(slog.DiscardHandler))
	s := &seen{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.called = true
		s.req, s.ok = From(r.Context())
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body in handler: %v", err)
		}
		s.body = string(b)
		w.WriteHeader(http.StatusNoContent)
	})
	mw, err := New(Options{
		Match:    func(*http.Request) bool { return matched },
		Problems: pw,
		Caller: func(context.Context) (caller.Caller, bool) {
			if c == nil {
				return caller.Caller{}, false
			}
			return *c, true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	middleware.BodyLimit(64<<10, pw)(mw(next)).ServeHTTP(rec, req)
	return rec, s
}

func request(key []string, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	for _, k := range key {
		r.Header.Add("Idempotency-Key", k)
	}
	return r
}

// problemCode returns the code of the problem in rec.
func problemCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct{ Code string }
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("problem body %q: %v", rec.Body, err)
	}
	return p.Code
}

func TestMiddlewareRefuses(t *testing.T) {
	t.Parallel()

	workload := &caller.Caller{Kind: caller.KindWorkload, ID: "spiffe://cluster.local/ns/a/sa/b"}
	const body = `{"status":"active"}`
	for _, tc := range []struct {
		name   string
		key    []string
		body   string
		status int
		code   string
	}{
		{"no key", nil, body, 422, "VALIDATION_FAILED"},
		{"empty key", []string{""}, body, 422, "VALIDATION_FAILED"},
		{"two keys", []string{"a", "b"}, body, 422, "VALIDATION_FAILED"},
		{"256 bytes", []string{strings.Repeat("k", 256)}, body, 422, "VALIDATION_FAILED"},
		{"a space", []string{"a b"}, body, 422, "VALIDATION_FAILED"},
		{"a control byte", []string{"a\x7fb"}, body, 422, "VALIDATION_FAILED"},
		{"a non-ASCII byte", []string{"a\xc3\xa9"}, body, 422, "VALIDATION_FAILED"},
		{"invalid JSON", []string{"k"}, `{"status":`, 422, "VALIDATION_FAILED"},
		{"a duplicate member", []string{"k"}, `{"a":1,"a":2}`, 422, "VALIDATION_FAILED"},
		{"over the body limit", []string{"k"}, `{"a":"` + strings.Repeat("x", 64<<10) + `"}`, 413, "VALIDATION_FAILED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec, s := serve(t, true, workload, request(tc.key, tc.body))
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.status, rec.Body)
			}
			if got := problemCode(t, rec); got != tc.code {
				t.Errorf("code = %q, want %q", got, tc.code)
			}
			if s.called {
				t.Error("the handler ran")
			}
		})
	}

	t.Run("no caller", func(t *testing.T) {
		t.Parallel()
		rec, s := serve(t, true, nil, request([]string{"k"}, body))
		if rec.Code < 500 || s.called {
			t.Errorf("status = %d, handler ran = %v; want a server error and no handler", rec.Code, s.called)
		}
	})
}

func TestMiddlewarePasses(t *testing.T) {
	t.Parallel()

	const body = `{ "status": "active" }`
	for _, tc := range []struct {
		name   string
		caller caller.Caller
		key    string
		want   string
	}{
		{"workload", caller.Caller{Kind: caller.KindWorkload, ID: "spiffe://a/b"}, "k-1", "workload:spiffe://a/b"},
		{"client", caller.Caller{Kind: caller.KindClient, ID: "support"}, strings.Repeat("~", 255), "client:support"},
		{"visible ASCII", caller.Caller{Kind: caller.KindClient, ID: "support"}, "!\"#$%&'()*+,-./09:;<=>?@AZ[\\]^_`az{|}~", "client:support"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := tc.caller
			rec, s := serve(t, true, &c, request([]string{tc.key}, body))
			if rec.Code != http.StatusNoContent || !s.called {
				t.Fatalf("status = %d, handler ran = %v; body %s", rec.Code, s.called, rec.Body)
			}
			if !s.ok {
				t.Fatal("From: no request")
			}
			hash, err := RequestHash(http.MethodPut, path, []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if s.req.Caller != tc.want || s.req.Key != tc.key || !bytes.Equal(s.req.Hash, hash) {
				t.Errorf("request = {%q, %q, %x}, want {%q, %q, %x}", s.req.Caller, s.req.Key, s.req.Hash, tc.want, tc.key, hash)
			}
			if s.body != body {
				t.Errorf("handler read body %q, want %q", s.body, body)
			}
		})
	}

	t.Run("empty body", func(t *testing.T) {
		t.Parallel()
		c := caller.Caller{Kind: caller.KindClient, ID: "support"}
		rec, s := serve(t, true, &c, request([]string{"k"}, ""))
		if rec.Code != http.StatusNoContent || !s.ok {
			t.Fatalf("status = %d, request = %v", rec.Code, s.ok)
		}
	})

	t.Run("unmatched", func(t *testing.T) {
		t.Parallel()
		rec, s := serve(t, false, nil, request(nil, "not json"))
		if rec.Code != http.StatusNoContent || !s.called || s.ok || s.body != "not json" {
			t.Errorf("status = %d, handler ran = %v, request = %v, body %q: want the request untouched",
				rec.Code, s.called, s.ok, s.body)
		}
	})
}

func TestNewRefuses(t *testing.T) {
	t.Parallel()
	pw := problem.New(slog.New(slog.DiscardHandler))
	match := func(*http.Request) bool { return true }
	for name, o := range map[string]Options{
		"no match":    {Problems: pw},
		"no problems": {Match: match},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// failingBody fails to read, as a body whose client went away.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// TestMiddlewareUnreadableBody: a body that cannot be read is the client's 422, not a logged
// server error.
func TestMiddlewareUnreadableBody(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	pw := problem.New(slog.New(slog.NewTextHandler(&logs, nil)))
	mw, err := New(Options{
		Match: func(*http.Request) bool { return true }, Problems: pw,
		Caller: func(context.Context) (caller.Caller, bool) {
			return caller.Caller{Kind: caller.KindClient, ID: "s"}, true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, path, failingBody{})
	req.Header.Set("Idempotency-Key", "k")
	rec := httptest.NewRecorder()
	called := false
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity || problemCode(t, rec) != "VALIDATION_FAILED" || called {
		t.Errorf("status %d, body %s, handler ran = %v; want 422 VALIDATION_FAILED", rec.Code, rec.Body, called)
	}
	if logs.Len() != 0 {
		t.Errorf("logged: %s", logs.String())
	}
}
