package postgres_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// resumeChallenge is a 3-attempt email_code resume challenge to the identifier.
func (e *flowsEnv) resumeChallenge(flowID, identifierID uuid.UUID, value string) flow.NewChallengeRecord {
	c := e.otpChallenge(flowID, identifierID, value, "123456")
	c.Purpose = flow.PurposeResume
	return c
}

// noLocksHeld runs fn in a transaction and fails the test when, after it, the transaction holds a
// row of flows or challenges locked: fn must lock nothing.
func (e *flowsEnv) noLocksHeld(t *testing.T, fn func(ctx context.Context) error) {
	t.Helper()
	e.do(t, func(ctx context.Context) error {
		if err := fn(ctx); err != nil {
			return err
		}
		for _, table := range []string{"flows", "challenges"} {
			var all, free int
			err := e.su.QueryRowContext(ctx, fmt.Sprintf(
				"SELECT (SELECT count(*) FROM %[1]s), (SELECT count(*) FROM (SELECT 1 FROM %[1]s FOR UPDATE SKIP LOCKED) x)",
				table)).Scan(&all, &free)
			if err != nil {
				return err
			}
			if all != free {
				t.Errorf("%s: %d rows locked", table, all-free)
			}
		}
		return nil
	})
}

func idsOf[T any](xs []T, id func(T) uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(xs))
	for _, x := range xs {
		out = append(out, id(x))
	}
	return out
}

func TestResumable(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	const email = "shared@example.org"
	fs, _ := e.sharedEmail(t, 4, email) // four pending accounts, oldest first

	// Not found: a sign_in flow, a closed one, one past expires_at, a retired identifier, another value.
	signIn := e.newAccount("", email)
	e.create(t, signIn)
	e.open(t, e.newFlow(signIn.ID, flow.KindSignIn, handle("sign-in")))
	more, _ := e.sharedEmail(t, 3, email)
	e.locked(t, more[0], func(ctx context.Context, f flow.Flow) error { return e.flows.Cancel(ctx, f.ID, flow.CloseReplaced) })
	e.exec(t, "UPDATE flows SET expires_at = now() - interval '1 second' WHERE id = ?", more[1].ID)
	e.exec(t, "UPDATE identifiers SET retired_at = now() WHERE account_id = ?", more[2].AccountID)
	other, _ := e.sharedEmail(t, 1, "other@example.org")

	var got []app.ResumeTarget
	e.noLocksHeld(t, func(ctx context.Context) (err error) {
		got, err = e.flows.Resumable(ctx, "email", email, 3)
		return err
	})
	want := []uuid.UUID{fs[3].ID, fs[2].ID, fs[1].ID}
	if d := cmp.Diff(want, idsOf(got, func(r app.ResumeTarget) uuid.UUID { return r.Flow.ID })); d != "" {
		t.Errorf("flows, newest first (-want +got):\n%s", d)
	}
	for _, r := range got {
		idID, _ := e.identifierOf(t, r.Flow.AccountID)
		if r.IdentifierID != idID || r.Flow.Kind != flow.KindRegistration || len(r.Flow.HandleHash) == 0 {
			t.Errorf("target %+v: want identifier %s", r, idID)
		}
	}
	if got, err := e.flows.Resumable(t.Context(), "email", "nobody@example.org", 3); err != nil || len(got) != 0 {
		t.Errorf("unknown value: %v, %v", got, err)
	}
	if got, err := e.flows.Resumable(t.Context(), "email", "other@example.org", 3); err != nil || len(got) != 1 || got[0].Flow.ID != other[0].ID {
		t.Errorf("other value: %v, %v", got, err)
	}
	if _, err := e.flows.Resumable(t.Context(), "email", email, 0); err == nil {
		t.Error("limit 0 accepted")
	}
}

func TestResumeCandidates(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	const email = "shared@example.org"
	fs, _ := e.sharedEmail(t, 6, email) // each also has a verify_identifier challenge, never a candidate
	var rs []flow.NewChallengeRecord
	for _, f := range fs {
		idID, _ := e.identifierOf(t, f.AccountID)
		r := e.resumeChallenge(f.ID, idID, email)
		e.openChallenges(t, f, r)
		rs = append(rs, r)
	}
	// Not candidates: a closed challenge, an expired one, one whose flow is closed, one whose flow
	// is past expires_at though not closed yet (the expiry job, TDD-02 §2.5), and an email_link one.
	e.exec(t, "UPDATE challenges SET closed_at = now(), secret = NULL WHERE id = ?", rs[5].ID)
	e.exec(t, "UPDATE challenges SET expires_at = now() - interval '1 second' WHERE id = ?", rs[4].ID)
	e.locked(t, fs[3], func(ctx context.Context, f flow.Flow) error { return e.flows.Cancel(ctx, f.ID, flow.CloseReplaced) })
	e.exec(t, "UPDATE flows SET expires_at = now() - interval '1 second' WHERE id = ?", fs[2].ID)
	more, _ := e.sharedEmail(t, 1, email)
	idID, _ := e.identifierOf(t, more[0].AccountID)
	link := e.resumeChallenge(more[0].ID, idID, email)
	link.Method, link.SecretMAC, link.Secret = flow.MethodEmailLink, []byte(fmt.Sprintf("link %s", link.ID)), flow.Secret("token")
	e.openChallenges(t, more[0], link)

	var got []app.ResumeCandidate
	e.noLocksHeld(t, func(ctx context.Context) (err error) {
		got, err = e.flows.ResumeCandidates(ctx, "email", email, 3)
		return err
	})
	want := []uuid.UUID{rs[1].ID, rs[0].ID}
	if d := cmp.Diff(want, idsOf(got, func(c app.ResumeCandidate) uuid.UUID { return c.Challenge.ID })); d != "" {
		t.Errorf("candidates, newest first (-want +got):\n%s", d)
	}
	for i, c := range got[:min(len(got), len(want))] {
		if c.Flow.ID != fs[1-i].ID || c.Challenge.Purpose != flow.PurposeResume || c.Challenge.FlowID != c.Flow.ID ||
			len(c.Challenge.SecretMAC) == 0 || c.Challenge.MaxAttempts != 3 {
			t.Errorf("candidate %d: %+v", i, c)
		}
	}

	// At most limit, newest first.
	extra, _ := e.sharedEmail(t, 3, email)
	for _, f := range extra {
		idID, _ := e.identifierOf(t, f.AccountID)
		e.openChallenges(t, f, e.resumeChallenge(f.ID, idID, email))
	}
	got, err := e.flows.ResumeCandidates(t.Context(), "email", email, 3)
	if err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff([]uuid.UUID{extra[2].ID, extra[1].ID, extra[0].ID},
		idsOf(got, func(c app.ResumeCandidate) uuid.UUID { return c.Flow.ID })); d != "" {
		t.Errorf("limited (-want +got):\n%s", d)
	}
	if got, err := e.flows.ResumeCandidates(t.Context(), "email", "nobody@example.org", 3); err != nil || len(got) != 0 {
		t.Errorf("unknown value: %v, %v", got, err)
	}
	if _, err := e.flows.ResumeCandidates(t.Context(), "email", email, 0); err == nil {
		t.Error("limit 0 accepted")
	}
}
