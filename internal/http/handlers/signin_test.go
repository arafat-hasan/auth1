package handlers_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/session"
	"github.com/arafat-hasan/auth1/internal/http/gen"
	"github.com/arafat-hasan/auth1/internal/http/handlers"
	"github.com/arafat-hasan/auth1/internal/testing/apitest"
)

// fakeSignIn records the command and answers with res.
type fakeSignIn struct {
	cmd app.SignInPassword
	res app.SignInResult
	err error
}

func (f *fakeSignIn) Password(_ context.Context, c app.SignInPassword) (app.SignInResult, error) {
	f.cmd = c
	return f.res, f.err
}

const signInBody = `{"client_id":"web","identifier":{"type":"email","value":"ada@example.org"},"password":"correct horse battery staple"}`

// signInPost serves POST /auth/v1/sessions with the device cookie and user agent, and checks the
// exchange against the contract.
func signInPost(t *testing.T, s handlers.SignIn, cookie string) response {
	t.Helper()
	h := flowRouter(t, handlers.MetadataOptions{Issuer: "https://id.example.com", BasePath: "/auth"}, nil, s)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/sessions", strings.NewReader(signInBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Browser/1.0")
	if cookie != "" {
		req.Header.Set("Cookie", app.DeviceCookieName+"="+cookie)
	}
	req.RemoteAddr = "192.0.2.7:4242"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	contract := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(signInBody))
	contract.Header.Set("Content-Type", "application/json")
	apitest.New(t).Check(t, contract, resp)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: b}
}

func tokensResult(body bool, device string) app.SignInResult {
	until := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	return app.SignInResult{Tokens: &app.SignedIn{
		Access:    app.AccessToken{Token: "header.claims.signature", ExpiresAt: time.Now().Add(15 * time.Minute)},
		ExpiresIn: 15 * time.Minute, SessionID: testFlow, Status: account.StatusSuspended, StatusUntil: &until,
		Refresh: session.Secret("refresh-token-value"), RefreshMaxAge: 720 * time.Hour, BodyTransport: body,
		DeviceCookie: device,
	}}
}

func TestSignInHandlerCookieTransport(t *testing.T) {
	t.Parallel()
	s := &fakeSignIn{res: tokensResult(false, "new-device-cookie")}
	resp := signInPost(t, s, "presented-cookie")
	b := resp.body
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, b)
	}
	if got := resp.header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", got)
	}
	want := []string{
		"__Secure-auth1_rt=refresh-token-value; Path=/auth/v1/sessions; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict",
		"__Host-auth1_dev=new-device-cookie; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Strict",
	}
	if diff := cmp.Diff(want, resp.header.Values("Set-Cookie")); diff != "" {
		t.Errorf("Set-Cookie (-want +got):\n%s", diff)
	}
	var body map[string]any
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	wantBody := map[string]any{"access_token": "header.claims.signature", "token_type": "Bearer", "expires_in": 900.0,
		"session_id": testFlow.String(), "account_status": "suspended", "status_until": "2026-12-01T00:00:00Z"}
	if diff := cmp.Diff(wantBody, body); diff != "" {
		t.Errorf("body (-want +got):\n%s", diff)
	}
	wantCmd := app.SignInPassword{ClientID: "web", Type: "email", Value: "ada@example.org",
		Password: flow.Secret("correct horse battery staple"), DeviceCookie: "presented-cookie", UserAgent: "Browser/1.0",
		IP: clientAddr}
	if diff := cmp.Diff(wantCmd, s.cmd, addrs); diff != "" {
		t.Errorf("command (-want +got):\n%s", diff)
	}
}

func TestSignInHandlerBodyTransport(t *testing.T) {
	t.Parallel()
	resp := signInPost(t, &fakeSignIn{res: tokensResult(true, "")}, "")
	b := resp.body
	if got := resp.header.Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Set-Cookie %v, want none for a native client", got)
	}
	var body gen.TokenResponse
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	if body.RefreshToken == nil || *body.RefreshToken != "refresh-token-value" {
		t.Errorf("refresh_token %v, want it in the body", body.RefreshToken)
	}
}

func TestSignInHandlerStep(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 11, 4, 12, 10, 0, 0, time.UTC)
	for _, code := range []app.StepCode{app.StepMFARequired, app.StepMFAEnrolmentRequired} {
		resp := signInPost(t, &fakeSignIn{res: app.SignInResult{Step: &app.SignInStep{
			Code: code, FlowID: testFlow, Handle: flow.Secret(testHandle), ExpiresAt: expires}}}, "")
		b := resp.body
		if resp.status != http.StatusAccepted || len(resp.header.Values("Set-Cookie")) != 0 {
			t.Fatalf("%s: status %d, cookies %v: %s", code, resp.status, resp.header.Values("Set-Cookie"), b)
		}
		var got gen.MfaStep
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		want := gen.MfaStep{Code: gen.MfaStepCode(code), FlowId: testFlow, Handle: testHandle, ExpiresAt: expires}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("%s body (-want +got):\n%s", code, diff)
		}
		if !slices.Contains([]string{"no-store"}, resp.header.Get("Cache-Control")) {
			t.Errorf("%s: Cache-Control %q, want no-store", code, resp.header.Get("Cache-Control"))
		}
	}
}

func TestSignInHandlerNotImplemented(t *testing.T) {
	t.Parallel()
	h := flowRouter(t, defaultMetadata, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions", strings.NewReader(signInBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status %d, want 501 without a sign-in", rec.Code)
	}
}
