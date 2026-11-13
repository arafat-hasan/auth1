package app_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
)

const resumeEmail = "resume@example.org"

func resumeCmd() app.RequestResume {
	return app.RequestResume{ClientID: "web", IdentifierType: "email", Value: "Resume@Example.org", IP: resumeIP}
}

const resumeMessage = "auth.registration_resume"

// TestRequestResumeSendsPerFlow (T-19, request half): a message goes to the address for each open
// flow holding it, at most 3, newest first, in one check of the send limits.
func TestRequestResumeSendsPerFlow(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	var flows []uuid.UUID
	for range 4 {
		flows = append(flows, e.register(t, resumeEmail).FlowID)
	}
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	rs := e.resumes(t)
	var got []uuid.UUID
	for _, r := range rs {
		got = append(got, r.FlowID)
		if r.Sends != 1 || !r.Open {
			t.Errorf("resume challenge %+v: want open, sent once", r)
		}
	}
	slices.SortFunc(got, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	if want := flows[1:]; !slices.Equal(got, want) {
		t.Errorf("resume challenges in flows %v; want the newest three %v", got, want)
	}
	ds := e.deliveries(t, resumeMessage)
	if len(ds) != 3 {
		t.Fatalf("%d resume messages; want 3", len(ds))
	}
	for _, d := range ds {
		if !slices.ContainsFunc(rs, func(r resumeRow) bool { return d.RequestID == r.ID.String()+":1" }) ||
			!strings.HasPrefix(d.Variables["code"].(string), "auth1:secret:") {
			t.Errorf("message %+v: want a resume code of one of the challenges", d)
		}
	}
	as := e.audits(t, "registration.resume_request")
	if len(as) != 3 {
		t.Fatalf("%d audit entries; want one per flow", len(as))
	}
	for _, a := range as {
		if a.Outcome != "success" || a.Details["kind"] != "registration" || a.Details["sent"] != true ||
			a.AccountID == nil || strings.Contains(strings.ToLower(a.Details["flow_id"].(string)), "@") {
			t.Errorf("audit %+v", a)
		}
	}
}

// TestRequestResumeReuses: a second request within the short window sends nothing and answers the
// same; after it, the same challenges, with their secrets, are sent again.
func TestRequestResumeReuses(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	e.register(t, resumeEmail)
	e.register(t, resumeEmail)
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	first := e.resumes(t)
	codes := map[uuid.UUID]string{}
	for _, r := range first {
		codes[r.ID] = string(e.code(t, r.ID))
	}
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatalf("second request: %v; want nil, as always", err)
	}
	if n := len(e.deliveries(t, resumeMessage)); n != 2 {
		t.Errorf("%d messages after a request within the short window; want still 2", n)
	}
	if as := e.audits(t, "registration.resume_request"); len(as) != 4 || as[2].Details["sent"] != false {
		t.Errorf("audits %+v; want the refused request's flows audited unsent", as)
	}
	e.age(t, 2*time.Minute)
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	again := e.resumes(t)
	if len(again) != 2 {
		t.Fatalf("%d resume challenges; want the 2 reused", len(again))
	}
	for _, r := range again {
		if r.Sends != 2 || codes[r.ID] != string(e.code(t, r.ID)) {
			t.Errorf("challenge %v: sends %d, secret kept %v; want reused", r.ID, r.Sends, codes[r.ID] == string(e.code(t, r.ID)))
		}
	}
}

// TestRequestResumeExpiredChallenge: an open resume challenge past its expiry is closed and a new
// one opened, with a new secret.
func TestRequestResumeExpiredChallenge(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	e.register(t, resumeEmail)
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	e.exec(t, "UPDATE challenges SET expires_at = now() - interval '1 second' WHERE purpose = 'resume'")
	e.age(t, 2*time.Minute)
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	rs := e.resumes(t)
	if len(rs) != 2 || rs[0].Open || rs[0].Secret != nil || !rs[1].Open || rs[1].Sends != 1 {
		t.Errorf("challenges %+v; want the expired one closed, erased, and a new one sent", rs)
	}
}

// TestRequestResumeLongWindow: with room for one more send in the hour, only the newest flow's
// message goes.
func TestRequestResumeLongWindow(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	for range 3 {
		e.register(t, resumeEmail)
	}
	// Four sends to the address 10 minutes ago: room for one in the hour, none in the minute.
	e.exec(t, "UPDATE challenge_sends SET sent_at = now() - interval '10 minutes'")
	e.exec(t, `INSERT INTO challenge_sends (challenge_id, send, target_bidx, sent_at)
		SELECT id, 2, target_bidx, now() - interval '10 minutes' FROM challenges WHERE purpose = 'verify_identifier' LIMIT 1`)
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	var sent []resumeRow
	for _, r := range e.resumes(t) {
		if r.Sends > 0 {
			sent = append(sent, r)
		}
	}
	if len(sent) != 1 || len(e.deliveries(t, resumeMessage)) != 1 {
		t.Fatalf("sent %+v; want one", sent)
	}
	var newest uuid.UUID
	if err := e.su.QueryRowContext(t.Context(), "SELECT id FROM flows ORDER BY created_at DESC LIMIT 1").Scan(&newest); err != nil {
		t.Fatal(err)
	}
	if sent[0].FlowID != newest {
		t.Errorf("sent to flow %v; want the newest, %v", sent[0].FlowID, newest)
	}
}

// TestRequestResumeNothingFound: an unknown value, one that does not normalise and an unknown type
// all answer as a known one does, and write nothing.
func TestRequestResumeNothingFound(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	e.register(t, resumeEmail)
	for name, edit := range map[string]func(*app.RequestResume){
		"unknown value": func(c *app.RequestResume) { c.Value = "nobody@example.org" },
		"not a value":   func(c *app.RequestResume) { c.Value = "not an address" },
		"unknown type":  func(c *app.RequestResume) { c.IdentifierType = "username" },
	} {
		c := resumeCmd()
		edit(&c)
		if err := e.reg.RequestResume(t.Context(), c); err != nil {
			t.Errorf("%s: %v; want nil", name, err)
		}
	}
	if rs, ds := e.resumes(t), e.deliveries(t, resumeMessage); len(rs) != 0 || len(ds) != 0 {
		t.Errorf("wrote %d challenges and %d messages; want none", len(rs), len(ds))
	}
}

// TestRequestResumeLimits: L-14 and L-8 refuse silently; an unknown client is VALIDATION_FAILED.
func TestRequestResumeLimits(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	e.register(t, resumeEmail)
	c := resumeCmd()
	c.ClientID = "nope"
	var de *domain.Error
	if err := e.reg.RequestResume(t.Context(), c); !errors.As(err, &de) || de.Code != domain.CodeValidationFailed {
		t.Errorf("unknown client: %v; want VALIDATION_FAILED", err)
	}
	key := app.IPKey(resumeIP)
	for _, rule := range []app.Rule{app.RuleResumeIP, app.RuleSendIP} {
		f := newResumeEnv(t)
		f.register(t, resumeEmail)
		for f.limiter.Hits(rule, key) < 1000 {
			if _, err := f.limiter.Hit(t.Context(), rule, key, app.RateLimit{Limit: 1000, Window: time.Hour}); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
			t.Errorf("%s refused: %v; want nil", rule, err)
		}
		if n := len(f.resumes(t)); n != 0 {
			t.Errorf("%s refused: %d challenges opened; want none", rule, n)
		}
	}
	if n := e.limiter.Hits(app.RuleResumeIP, key); n != 0 {
		t.Errorf("an unknown client counted %d resume hits", n)
	}
}

// TestRequestResumeString: the command prints, formats and logs without the value.
func TestRequestResumeString(t *testing.T) {
	t.Parallel()
	c := resumeCmd()
	for _, s := range []string{c.String(), c.GoString(), fmt.Sprintf("%v %+v %#v %s", c, c, c, c), c.LogValue().String()} {
		if strings.Contains(strings.ToLower(s), "resume@example.org") {
			t.Errorf("%q holds the value", s)
		}
	}
}
