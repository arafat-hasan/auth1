package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/http/gen"
)

func (f *fakeRegistration) RequestResume(_ context.Context, c app.RequestResume) error {
	f.request = c
	return f.err
}

func (f *fakeRegistration) VerifyResume(_ context.Context, c app.VerifyResume) (app.FlowResumed, error) {
	f.resume = c
	return f.resumed, f.err
}

const resumeBody = `{"client_id":"web","identifier":{"type":"email","value":"someone@example.com"}}`

func TestRequestResumeHandler(t *testing.T) {
	t.Parallel()
	reg := &fakeRegistration{}
	resp := post(t, regRouter(t, reg), "/v1/registrations/resume", resumeBody)
	if resp.status != http.StatusAccepted || len(resp.body) != 0 {
		t.Fatalf("status %d: %s; want 202 with no body", resp.status, resp.body)
	}
	want := app.RequestResume{ClientID: "web", IdentifierType: "email", Value: "someone@example.com", IP: clientAddr}
	if diff := cmp.Diff(want, reg.request, addrs); diff != "" {
		t.Errorf("command (-want +got):\n%s", diff)
	}
}

func TestVerifyResumeHandler(t *testing.T) {
	t.Parallel()
	expires := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	accepted := false
	for _, tt := range []struct {
		name    string
		resumed app.FlowResumed
		want    gen.FlowResumed
	}{
		{"registration", app.FlowResumed{FlowID: testFlow, Kind: flow.KindRegistration, Handle: flow.Secret(testHandle),
			PendingTypes: []string{}, ExpiresAt: expires},
			gen.FlowResumed{FlowId: testFlow, Kind: gen.FlowResumedKind("registration"), Handle: testHandle,
				PendingTypes: []string{}, ExpiresAt: expires}},
		{"invitation", app.FlowResumed{FlowID: testFlow, Kind: flow.KindInvitation, Accepted: &accepted,
			Handle: flow.Secret(testHandle), PendingTypes: []string{"phone"}, ExpiresAt: expires},
			gen.FlowResumed{FlowId: testFlow, Kind: gen.FlowResumedKind("invitation"), Accepted: &accepted,
				Handle: testHandle, PendingTypes: []string{"phone"}, ExpiresAt: expires}},
	} {
		reg := &fakeRegistration{resumed: tt.resumed}
		resp := post(t, regRouter(t, reg), "/v1/registrations/resume/verify",
			`{"identifier":{"type":"email","value":"someone@example.com"},"code":"123456"}`)
		if resp.status != http.StatusOK {
			t.Fatalf("%s: status %d: %s", tt.name, resp.status, resp.body)
		}
		var got gen.FlowResumed
		if err := json.Unmarshal(resp.body, &got); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(tt.want, got); diff != "" {
			t.Errorf("%s: body (-want +got):\n%s", tt.name, diff)
		}
		want := app.VerifyResume{IdentifierType: "email", Value: "someone@example.com", Code: flow.Secret("123456"), IP: clientAddr}
		if diff := cmp.Diff(want, reg.resume, addrs); diff != "" {
			t.Errorf("%s: command (-want +got):\n%s", tt.name, diff)
		}
	}
}

func TestConfirmResumeLinkHandler(t *testing.T) {
	t.Parallel()
	reg := &fakeRegistration{link: app.LinkConfirmed{
		Purpose: flow.PurposeResume, FlowID: testFlow, Complete: true, PendingTypes: []string{}, Handle: flow.Secret(testHandle),
	}}
	resp := post(t, regRouter(t, reg), "/v1/verification-links/confirm", `{"token":"`+strings.Repeat("t", 43)+`"}`)
	want := `{"complete":true,"flow_id":"` + testFlow.String() + `","handle":"` + testHandle +
		`","pending_types":[],"purpose":"resume"}` + "\n"
	if resp.status != http.StatusOK || string(resp.body) != want {
		t.Errorf("status %d, body %s; want %s", resp.status, resp.body, want)
	}
}

// TestResumeErrors: the codes the resume operations give, each checked against the contract.
func TestResumeErrors(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		path, body string
		err        *domain.Error
		status     int
	}{
		{"/v1/registrations/resume", resumeBody, &domain.Error{Code: domain.CodeValidationFailed, Detail: "x",
			Fields: []domain.FieldError{{Field: "client_id", Code: domain.FieldUnknown}}}, 422},
		{"/v1/registrations/resume/verify", `{"identifier":{"type":"email","value":"a@example.com"},"code":"123456"}`,
			&domain.Error{Code: domain.CodeCodeInvalid, Detail: "the code is wrong"}, 400},
		{"/v1/registrations/resume/verify", `{"identifier":{"type":"email","value":"a@example.com"},"code":"123456"}`,
			&domain.Error{Code: domain.CodeIdentifierTaken, Detail: "x"}, 409},
		{"/v1/registrations/resume/verify", `{"identifier":{"type":"email","value":"a@example.com"},"code":"123456"}`,
			&domain.Error{Code: domain.CodeRateLimited, Detail: "x", RetryAfter: time.Hour}, 429},
	} {
		resp := post(t, regRouter(t, &fakeRegistration{err: tt.err}), tt.path, tt.body)
		if resp.status != tt.status || !strings.Contains(string(resp.body), `"code":"`+string(tt.err.Code)+`"`) {
			t.Errorf("%s %s: status %d, body %s", tt.path, tt.err.Code, resp.status, resp.body)
		}
		if tt.err.Code == domain.CodeCodeInvalid && strings.Contains(string(resp.body), "attempts_left") {
			t.Errorf("CODE_INVALID tells the attempts left: %s", resp.body)
		}
	}
}
