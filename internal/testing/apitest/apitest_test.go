package apitest

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recorder is a TB that keeps what it is told, so a test can check the harness's verdict.
type recorder struct {
	errs []string
}

func (*recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.errs = append(r.errs, "fatal: "+fmt.Sprintf(format, args...))
}

// answer returns a handler that reads the request body, as a real one does, and answers status
// with a JSON body of contentType.
func answer(status int, contentType, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

const me = `{"account_id":"0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b","display_name":"A","status":"active",
"roles":[],"locale":"en","identifiers":[],"mfa_enrolled":false,"recovery_codes_remaining":0}`

func getMe() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer x")
	return req
}

func signIn() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(
		`{"client_id":"web","identifier":{"type":"email","value":"someone@example.com"},"password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestServe(t *testing.T) {
	t.Parallel()

	v := New(t)
	tests := []struct {
		name    string
		req     *http.Request
		h       http.Handler
		wantErr string // a substring of one reported error; "" for none
	}{
		{name: "matching response", req: getMe(), h: answer(200, "application/json", me)},
		{name: "response missing a required member", req: getMe(),
			h:       answer(200, "application/json", strings.Replace(me, `"display_name":"A",`, "", 1)),
			wantErr: "response to GET /v1/me"},
		{name: "body read by the handler, matching problem", req: signIn(),
			h: answer(401, "application/problem+json", `{"type":"about:blank","title":"Unauthorized","status":401,"code":"INVALID_CREDENTIALS"}`)},
		{name: "body read by the handler, problem without code", req: signIn(),
			h:       answer(401, "application/problem+json", `{"type":"about:blank","title":"Unauthorized","status":401}`),
			wantErr: "response to POST /v1/sessions"},
		{name: "request breaking its schema", req: func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(`{"client_id":"web"}`))
			req.Header.Set("Content-Type", "application/json")
			return req
		}(), h: answer(401, "application/problem+json", `{"type":"about:blank","title":"Unauthorized","status":401,"code":"INVALID_CREDENTIALS"}`),
			wantErr: "request POST /v1/sessions"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := &recorder{}
			resp := v.Serve(rec, tt.h, tt.req)
			defer func() { _ = resp.Body.Close() }()

			if tt.wantErr == "" {
				if len(rec.errs) != 0 {
					t.Errorf("reported errors for a valid exchange:\n%s", strings.Join(rec.errs, "\n"))
				}
				return
			}
			if len(rec.errs) == 0 {
				t.Fatal("reported no error")
			}
			for _, e := range rec.errs {
				if !strings.Contains(e, tt.wantErr) {
					t.Errorf("error %q does not contain %q", e, tt.wantErr)
				}
			}
		})
	}
}

// TestServeReturnsResponse checks that the caller still gets the handler's response.
func TestServeReturnsResponse(t *testing.T) {
	t.Parallel()

	resp := New(t).Serve(t, answer(200, "application/json", me), getMe())
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || string(body) != me {
		t.Errorf("response %d %q, want 200 and the handler's body", resp.StatusCode, body)
	}
}
