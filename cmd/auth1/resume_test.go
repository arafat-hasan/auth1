package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const resumeType = "auth.registration_resume"

// resumeMessages returns the resume messages among msgs.
func resumeMessages(msgs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, m := range msgs {
		if m["type"] == resumeType {
			out = append(out, m)
		}
	}
	return out
}

// flowOf returns the flow of the challenge a message was sent for, from its request id.
func (s regServer) flowOf(t *testing.T, m map[string]any) string {
	t.Helper()
	chID, _, _ := strings.Cut(m["request_id"].(string), ":")
	var flowID string
	if err := s.db.QueryRowContext(t.Context(), "SELECT flow_id::text FROM challenges WHERE id = $1", chID).Scan(&flowID); err != nil {
		t.Fatal(err)
	}
	return flowID
}

// ageSends moves every send two hours back, so the send and resend limits leave room.
func (s regServer) ageSends(t *testing.T) {
	t.Helper()
	for _, q := range []string{
		"UPDATE challenge_sends SET sent_at = sent_at - interval '2 hours'",
		"UPDATE challenges SET last_sent_at = last_sent_at - interval '2 hours' WHERE last_sent_at IS NOT NULL",
	} {
		if _, err := s.db.ExecContext(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
}

// TestT19Resume is acceptance test T-19 by code: two registrations hold one phone and lose their
// handles; resume sends a message for each; one code resumes its flow with a new handle, and the
// old handle is refused. An unknown value gets 202 and nothing.
func TestT19Resume(t *testing.T) {
	s := startRegServer(t)
	flowA, handleA := s.register(t, `{"email":"a@example.org","phone":"+44 7400 123456"}`)
	s.register(t, `{"email":"b@example.org","phone":"+44 7400 123456"}`)
	before := len(s.messages(t, regPhone, 1))
	s.ageSends(t)

	s.post(t, "/v1/registrations/resume", `{"client_id":"web","identifier":{"type":"phone","value":"+44 7400 123456"}}`).
		want(t, http.StatusAccepted, "")
	resumes := resumeMessages(s.messages(t, regPhone, before+2))
	if len(resumes) != 2 {
		t.Fatalf("%d resume messages; want one per flow, 2", len(resumes))
	}
	var code string
	for _, m := range resumes {
		if s.flowOf(t, m) == flowA {
			code = variable(t, m, "code")
		}
	}
	if code == "" {
		t.Fatal("no resume message for the first flow")
	}

	a := s.post(t, "/v1/registrations/resume/verify", `{"identifier":{"type":"phone","value":"+447400123456"},"code":"`+code+`"}`)
	a.want(t, http.StatusOK, "")
	newHandle, _ := a.body["handle"].(string)
	if a.body["flow_id"] != flowA || a.body["kind"] != "registration" || newHandle == "" || newHandle == handleA {
		t.Fatalf("resumed %s; want flow %s with a new handle", a.raw, flowA)
	}
	if p, _ := a.body["pending_types"].([]any); len(p) != 1 || p[0] != "email" {
		t.Errorf("pending_types %v; want [email]: the phone is verified", a.body["pending_types"])
	}
	s.resend(t, flowA, handleA, "email").want(t, http.StatusGone, "CHALLENGE_CLOSED")
	s.resend(t, flowA, newHandle, "email").want(t, http.StatusAccepted, "")

	// The code once more, and a code for nothing: the same CODE_INVALID, no attempts left told.
	for _, body := range []string{
		`{"identifier":{"type":"phone","value":"+447400123456"},"code":"` + code + `"}`,
		`{"identifier":{"type":"phone","value":"+447400999999"},"code":"123456"}`,
	} {
		a := s.post(t, "/v1/registrations/resume/verify", body)
		a.want(t, http.StatusBadRequest, "CODE_INVALID")
		if _, ok := a.body["attempts_left"]; ok {
			t.Errorf("CODE_INVALID tells the attempts left: %s", a.raw)
		}
	}

	// An unknown value: 202, and nothing is sent.
	s.post(t, "/v1/registrations/resume", `{"client_id":"web","identifier":{"type":"phone","value":"+44 7400 999999"}}`).
		want(t, http.StatusAccepted, "")
	time.Sleep(500 * time.Millisecond) // the relay would have sent it by now
	if _, body := get(t, s.api+"/dev/messages?to="+url.QueryEscape("+447400999999")); strings.Contains(body, resumeType) {
		t.Errorf("a message went to an unknown value: %s", body)
	}
}

// TestResumeLinkThroughAPI is T-19 by link: an email verified by link gets a resume link, which
// /verification-links/confirm takes, answering the new handle.
func TestResumeLinkThroughAPI(t *testing.T) {
	s := startRegServer(t)
	flowID, handle := s.register(t, `{"email":"Link@Example.org"}`)
	s.messages(t, "link@example.org", 1)
	s.ageSends(t)
	s.post(t, "/v1/registrations/resume", `{"client_id":"web","identifier":{"type":"email","value":"link@example.org"}}`).
		want(t, http.StatusAccepted, "")
	resumes := resumeMessages(s.messages(t, "link@example.org", 2))
	if len(resumes) != 1 {
		t.Fatalf("%d resume messages; want 1", len(resumes))
	}
	a := s.post(t, "/v1/verification-links/confirm", `{"token":"`+variable(t, resumes[0], "link")+`"}`)
	a.want(t, http.StatusOK, "")
	newHandle, _ := a.body["handle"].(string)
	if a.body["purpose"] != "resume" || a.body["flow_id"] != flowID || a.body["complete"] != true || newHandle == "" {
		t.Fatalf("confirmed %s; want the resumed flow with a new handle", a.raw)
	}
	s.resend(t, flowID, handle, "email").want(t, http.StatusGone, "CHALLENGE_CLOSED")
}

// TestResumeUnknownClient: the request itself is checked; the value never is.
func TestResumeUnknownClient(t *testing.T) {
	s := startRegServer(t)
	s.post(t, "/v1/registrations/resume", `{"client_id":"nope","identifier":{"type":"email","value":"x@example.org"}}`).
		want(t, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}
