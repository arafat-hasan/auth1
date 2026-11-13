package app_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// resumed registers n flows holding resumeEmail and requests a resume: it returns the
// registrations, oldest first, and the resume challenges, in the same order.
func (e *resumeEnv) resumed(t *testing.T, n int) ([]app.RegistrationStarted, []resumeRow) {
	t.Helper()
	var ss []app.RegistrationStarted
	for range n {
		ss = append(ss, e.register(t, resumeEmail))
	}
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	rs := e.resumes(t)
	if len(rs) != n {
		t.Fatalf("%d resume challenges; want %d", len(rs), n)
	}
	slices.SortFunc(rs, func(a, b resumeRow) int {
		return slices.IndexFunc(ss, func(s app.RegistrationStarted) bool { return s.FlowID == a.FlowID }) -
			slices.IndexFunc(ss, func(s app.RegistrationStarted) bool { return s.FlowID == b.FlowID })
	})
	return ss, rs
}

func verifyCmd(code flow.Secret) app.VerifyResume {
	return app.VerifyResume{IdentifierType: "email", Value: "RESUME@example.org", Code: code, IP: resumeIP}
}

// notCode is a code that is not code.
func notCode(code flow.Secret) flow.Secret {
	b := []byte(string(code))
	b[0] = '0' + (b[0]-'0'+1)%10
	return b
}

// checkCodeInvalid fails unless err is exactly the uniform resume failure: CODE_INVALID with no
// attempts left, no fields and no retry time (I-20).
func checkCodeInvalid(t *testing.T, name string, err error) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("%s: %v; want CODE_INVALID", name, err)
	}
	want := &domain.Error{Code: domain.CodeCodeInvalid, Detail: "the code is wrong"}
	if d := cmp.Diff(want, de); d != "" {
		t.Errorf("%s (-want +got):\n%s", name, d)
	}
}

// TestVerifyResumePicksFlow (T-19, verify half): the code of one flow resumes that flow: its
// identifier is verified, its handle replaced and the old one refused. The other candidates stay
// open, the try counted on them too.
func TestVerifyResumePicksFlow(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	ss, rs := e.resumed(t, 3)
	used := e.code(t, rs[1].ID)
	got, err := e.reg.VerifyResume(t.Context(), verifyCmd(used))
	if err != nil {
		t.Fatal(err)
	}
	if got.FlowID != ss[1].FlowID || got.Kind != flow.KindRegistration || got.Accepted != nil ||
		len(got.Handle) != 43 || len(got.PendingTypes) != 0 || !got.ExpiresAt.Equal(ss[1].ExpiresAt) {
		t.Errorf("resumed %+v; want flow %v with a new handle and nothing pending", got, ss[1].FlowID)
	}
	old := sha256.Sum256(ss[1].Handle)
	if _, err := e.flows.Find(t.Context(), ss[1].FlowID, old[:]); !hasDomainCode(err, domain.CodeChallengeClosed) {
		t.Errorf("old handle: %v; want CHALLENGE_CLOSED", err)
	}
	h := sha256.Sum256(got.Handle)
	if _, err := e.flows.Find(t.Context(), ss[1].FlowID, h[:]); err != nil {
		t.Errorf("new handle: %v", err)
	}
	after := e.resumes(t)
	for _, r := range after {
		switch r.ID {
		case rs[1].ID:
			if r.Open || !r.Consumed || r.Secret != nil {
				t.Errorf("matched challenge %+v; want consumed, erased (I-5)", r)
			}
		default:
			if !r.Open || r.Attempts != 1 {
				t.Errorf("other candidate %+v; want open with the try counted", r)
			}
		}
	}
	var verified bool
	if err := e.su.QueryRowContext(t.Context(), `SELECT verified_at IS NOT NULL FROM identifiers i
		JOIN flows f ON f.account_id = i.account_id WHERE f.id = ?`, ss[1].FlowID).Scan(&verified); err != nil || !verified {
		t.Errorf("identifier verified: %v, %v", verified, err)
	}
	var events int
	if err := e.su.QueryRowContext(t.Context(), `SELECT count(*) FROM outbox o JOIN flows f ON f.account_id = o.subject
		WHERE f.id = ? AND o.type = 'account.identifier_verified'`, ss[1].FlowID).Scan(&events); err != nil || events != 1 {
		t.Errorf("%d identifier_verified events, %v; want 1", events, err)
	}
	as := e.audits(t, "registration.resume")
	if len(as) != 1 || as[0].Outcome != "success" || as[0].Details["flow_id"] != ss[1].FlowID.String() ||
		as[0].Details["kind"] != "registration" {
		t.Errorf("audits %+v; want one success naming the flow", as)
	}
	// The used code resumes nothing again. Another candidate's code still matches its flow, but
	// the value is now verified by the resumed account: IDENTIFIER_TAKEN (I-1).
	_, err = e.reg.VerifyResume(t.Context(), verifyCmd(used))
	checkCodeInvalid(t, "the used code again", err)
	if _, err := e.reg.VerifyResume(t.Context(), verifyCmd(e.codeOf(t, e.resumes(t), rs[0].ID))); !hasDomainCode(err, domain.CodeIdentifierTaken) {
		t.Errorf("another candidate's code after one resumed: %v; want IDENTIFIER_TAKEN", err)
	}
}

// codeOf is code, for a challenge still open in rows.
func (e *resumeEnv) codeOf(t *testing.T, rows []resumeRow, id uuid.UUID) flow.Secret {
	t.Helper()
	for _, r := range rows {
		if r.ID == id && r.Open {
			return e.code(t, id)
		}
	}
	t.Fatalf("challenge %v is not open", id)
	return nil
}

// TestVerifyResumeAttemptsAcrossCandidates (I-4): with 3 flows holding the value, a wrong code
// counts on every candidate, so the wrong tries in total stay at max_attempts, not 3 × it. The
// last closes every candidate, erasing its secret (I-5), and a right code is refused after.
func TestVerifyResumeAttemptsAcrossCandidates(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	_, rs := e.resumed(t, 3)
	right := e.code(t, rs[2].ID)
	for i := range challengeRules.MaxAttempts {
		_, err := e.reg.VerifyResume(t.Context(), verifyCmd(notCode(right)))
		checkCodeInvalid(t, fmt.Sprintf("wrong try %d", i+1), err)
	}
	for _, r := range e.resumes(t) {
		if r.Open || r.Consumed || r.Attempts != challengeRules.MaxAttempts || r.Secret != nil {
			t.Errorf("after %d wrong tries: %+v; want every candidate exhausted and erased", challengeRules.MaxAttempts, r)
		}
	}
	_, err := e.reg.VerifyResume(t.Context(), verifyCmd(right))
	checkCodeInvalid(t, "right code after the tries ran out", err)
}

// TestVerifyResumeUniformFailure (I-20): no candidates, open candidates, exhausted candidates and a
// value that does not normalise all answer the same CODE_INVALID, without attempts_left.
func TestVerifyResumeUniformFailure(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	_, rs := e.resumed(t, 2)
	code := e.code(t, rs[0].ID)
	cases := []struct {
		name string
		cmd  app.VerifyResume
	}{
		{"no candidates", app.VerifyResume{IdentifierType: "email", Value: "nobody@example.org", Code: code, IP: resumeIP}},
		{"not a value", app.VerifyResume{IdentifierType: "email", Value: "not an address", Code: code, IP: resumeIP}},
		{"unknown type", app.VerifyResume{IdentifierType: "username", Value: "someone", Code: code, IP: resumeIP}},
		{"open candidates", verifyCmd(notCode(code))},
		{"open candidates, again", verifyCmd(notCode(code))},
		{"exhausted candidates", verifyCmd(notCode(code))},
		{"none left", verifyCmd(code)},
	}
	for _, c := range cases {
		_, err := e.reg.VerifyResume(t.Context(), c.cmd)
		checkCodeInvalid(t, c.name, err)
	}
	if as := e.audits(t, "registration.resume"); len(as) == 0 || slices.ContainsFunc(as, func(a auditRow) bool {
		return a.Outcome != "failure" || a.Details["code"] != "CODE_INVALID" || strings.Contains(fmt.Sprint(a.Details), "@")
	}) {
		t.Errorf("failure audits %+v; want CODE_INVALID, no value", as)
	}
}

// TestVerifyResumeFactorFailures (L-11, L-12): a failure counts once against each candidate's
// account; an account at the limit is not compared, so its right code fails too, with the same
// answer. L-12 counts every attempt per IP first.
func TestVerifyResumeFactorFailures(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	ss, rs := e.resumed(t, 2)
	failures := func() []int {
		var out []int
		for _, s := range ss {
			var n int
			if err := e.su.QueryRowContext(t.Context(), `SELECT a.factor_failures FROM accounts a
				JOIN flows f ON f.account_id = a.id WHERE f.id = ?`, s.FlowID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			out = append(out, n)
		}
		return out
	}
	code := e.code(t, rs[1].ID)
	_, err := e.reg.VerifyResume(t.Context(), verifyCmd(notCode(code)))
	checkCodeInvalid(t, "wrong code", err)
	if got := failures(); !slices.Equal(got, []int{1, 1}) {
		t.Errorf("factor failures %v; want one on each candidate's account", got)
	}
	e.exec(t, `UPDATE accounts SET factor_failures = 10, factor_failures_since = now()
		WHERE id = (SELECT account_id FROM flows WHERE id = ?)`, ss[1].FlowID)
	_, err = e.reg.VerifyResume(t.Context(), verifyCmd(code))
	checkCodeInvalid(t, "right code on an account at L-11", err)
	if n := e.limiter.Hits(app.RuleVerifyIP, app.IPKey(resumeIP)); n != 2 {
		t.Errorf("L-12 counted %d attempts; want 2", n)
	}
	for e.limiter.Hits(app.RuleVerifyIP, app.IPKey(resumeIP)) < 1000 {
		if _, err := e.limiter.Hit(t.Context(), app.RuleVerifyIP, app.IPKey(resumeIP), app.RateLimit{Limit: 1000, Window: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.reg.VerifyResume(t.Context(), verifyCmd(code)); !hasDomainCode(err, domain.CodeRateLimited) {
		t.Errorf("past L-12: %v; want RATE_LIMITED", err)
	}
}

// TestVerifyResumeVerifiedIdentifier: resuming a flow whose identifier is verified already replaces
// the handle and emits nothing.
func TestVerifyResumeVerifiedIdentifier(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	s := e.register(t, resumeEmail)
	var vc uuid.UUID
	if err := e.su.QueryRowContext(t.Context(), "SELECT id FROM challenges WHERE purpose = 'verify_identifier'").Scan(&vc); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.VerifyCode(t.Context(), app.VerifyRegistrationCode{FlowID: s.FlowID, Handle: s.Handle,
		IdentifierType: "email", Code: e.code(t, vc), IP: resumeIP}); err != nil {
		t.Fatal(err)
	}
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	rs := e.resumes(t)
	got, err := e.reg.VerifyResume(t.Context(), verifyCmd(e.code(t, rs[0].ID)))
	if err != nil || got.FlowID != s.FlowID || len(got.PendingTypes) != 0 {
		t.Fatalf("VerifyResume = %+v, %v", got, err)
	}
	var events int
	if err := e.su.QueryRowContext(t.Context(), "SELECT count(*) FROM outbox WHERE type = 'account.identifier_verified'").Scan(&events); err != nil || events != 1 {
		t.Errorf("%d identifier_verified events; want only registration's", events)
	}
}

// TestVerifyResumeIdentifierTaken (I-1): when another account verified the value first, the right
// code is IDENTIFIER_TAKEN, the challenge consumed, and the handle is not replaced.
func TestVerifyResumeIdentifierTaken(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	ss, rs := e.resumed(t, 2)
	e.exec(t, `UPDATE identifiers SET verified_at = now()
		WHERE account_id = (SELECT account_id FROM flows WHERE id = ?)`, ss[0].FlowID)
	_, err := e.reg.VerifyResume(t.Context(), verifyCmd(e.code(t, rs[1].ID)))
	if !hasDomainCode(err, domain.CodeIdentifierTaken) {
		t.Fatalf("VerifyResume = %v; want IDENTIFIER_TAKEN", err)
	}
	for _, r := range e.resumes(t) {
		if r.ID == rs[1].ID && (r.Open || !r.Consumed) {
			t.Errorf("challenge %+v; want consumed", r)
		}
	}
	old := sha256.Sum256(ss[1].Handle)
	if _, err := e.flows.Find(t.Context(), ss[1].FlowID, old[:]); err != nil {
		t.Errorf("the handle was replaced: %v", err)
	}
}

// TestVerifyResumeInvitation: an invitation not yet accepted says so.
func TestVerifyResumeInvitation(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	s := e.register(t, resumeEmail)
	e.exec(t, `UPDATE flows SET kind = 'invitation', state = '{"roles": [], "accepted": false, "pending_types": ["email"]}'
		WHERE id = ?`, s.FlowID)
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	got, err := e.reg.VerifyResume(t.Context(), verifyCmd(e.code(t, e.resumes(t)[0].ID)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != flow.KindInvitation || got.Accepted == nil || *got.Accepted {
		t.Errorf("resumed %+v; want an invitation not accepted", got)
	}
}

// TestVerifyResumeString: the command prints, formats and logs without the value or the code.
func TestVerifyResumeString(t *testing.T) {
	t.Parallel()
	c := verifyCmd(flow.Secret("246810"))
	for _, s := range []string{c.String(), fmt.Sprintf("%v %+v %#v %s", c, c, c, c), c.LogValue().String()} {
		if strings.Contains(strings.ToLower(s), "resume@example.org") || strings.Contains(s, "246810") {
			t.Errorf("%q holds the value or the code", s)
		}
	}
}

// TestConfirmResumeLink (T-19 by link): an emailed resume link verifies the identifier and
// replaces the handle; the old handle is refused and the link works once.
func TestConfirmResumeLink(t *testing.T) {
	t.Parallel()
	e := newResumeEnvWith(t, flow.MethodEmailLink)
	s := e.register(t, resumeEmail)
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	rs := e.resumes(t)
	if len(rs) != 1 {
		t.Fatalf("%d resume challenges; want 1", len(rs))
	}
	if ds := e.deliveries(t, resumeMessage); len(ds) != 1 || ds[0].Variables["link"] != "auth1:link:"+rs[0].ID.String() {
		t.Fatalf("messages %+v; want the resume link", ds)
	}
	token := e.code(t, rs[0].ID)
	got, err := e.reg.ConfirmLink(t.Context(), app.ConfirmLink{Token: token, IP: resumeIP})
	if err != nil {
		t.Fatal(err)
	}
	if got.Purpose != flow.PurposeResume || got.FlowID != s.FlowID || !got.Complete || len(got.PendingTypes) != 0 ||
		len(got.Handle) != 43 {
		t.Errorf("confirmed %+v; want the resumed flow, complete, with a new handle", got)
	}
	old := sha256.Sum256(s.Handle)
	if _, err := e.flows.Find(t.Context(), s.FlowID, old[:]); !hasDomainCode(err, domain.CodeChallengeClosed) {
		t.Errorf("old handle: %v; want CHALLENGE_CLOSED", err)
	}
	h := sha256.Sum256(got.Handle)
	if _, err := e.flows.Find(t.Context(), s.FlowID, h[:]); err != nil {
		t.Errorf("new handle: %v", err)
	}
	if _, err := e.reg.ConfirmLink(t.Context(), app.ConfirmLink{Token: token, IP: resumeIP}); !hasDomainCode(err, domain.CodeChallengeClosed) {
		t.Errorf("the link again: %v; want CHALLENGE_CLOSED", err)
	}
}

// TestRequestResumeRefusedOpensNoCandidate: a resume whose send is refused (here in the L-9
// cooldown after the candidates ran out of tries) leaves no open resume challenge: a code nobody
// received must not be one an attacker can guess for a handle (I-20).
func TestRequestResumeRefusedOpensNoCandidate(t *testing.T) {
	t.Parallel()
	e := newResumeEnv(t)
	_, rs := e.resumed(t, 2)
	right := e.code(t, rs[0].ID)
	for range challengeRules.MaxAttempts {
		_, err := e.reg.VerifyResume(t.Context(), verifyCmd(notCode(right)))
		checkCodeInvalid(t, "wrong", err)
	}
	e.age(t, 2*time.Minute) // the short window has room; the cooldown has 13 minutes left
	if err := e.reg.RequestResume(t.Context(), resumeCmd()); err != nil {
		t.Fatal(err)
	}
	for _, r := range e.resumes(t) {
		if r.Open {
			t.Errorf("challenge %+v is open though its send was refused", r)
		}
	}
	if n := len(e.deliveries(t, resumeMessage)); n != 2 {
		t.Errorf("%d resume messages; want the first 2 only", n)
	}
}
