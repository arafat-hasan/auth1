package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// identifierOf returns the id and value of the account's email identifier.
func (e *flowsEnv) identifierOf(t *testing.T, accountID uuid.UUID) (uuid.UUID, string) {
	t.Helper()
	ids, err := e.repo.Identifiers(t.Context(), accountID)
	if err != nil || len(ids) == 0 {
		t.Fatalf("identifiers: %v %v", ids, err)
	}
	return ids[0].ID, ids[0].Value
}

// otpChallenge is a 3-attempt email_code challenge to the identifier, with code as its secret.
func (e *flowsEnv) otpChallenge(flowID, identifierID uuid.UUID, value, code string) flow.NewChallengeRecord {
	id := e.ids.New()
	return flow.NewChallengeRecord{
		ID: id, FlowID: flowID, Purpose: flow.PurposeVerifyIdentifier, Method: flow.MethodEmailCode,
		IdentifierID: &identifierID, TargetType: "email", TargetValue: value,
		SecretMAC: crypto.SHA256([]byte("otp:" + id.String() + code)), Secret: flow.Secret(code),
		MaxAttempts: 3, ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Truncate(time.Microsecond),
	}
}

// linkChallenge is an email_link challenge to a value under change, with token as its secret.
func (e *flowsEnv) linkChallenge(flowID uuid.UUID, value, token string) flow.NewChallengeRecord {
	return flow.NewChallengeRecord{
		ID: e.ids.New(), FlowID: flowID, Purpose: flow.PurposeEmailChangeNew, Method: flow.MethodEmailLink,
		TargetType: "email", TargetValue: value,
		SecretMAC: crypto.SHA256([]byte(token)), Secret: flow.Secret(token),
		MaxAttempts: 1, ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond),
	}
}

// openChallenges opens cs in the flow f, under the account and flow locks.
func (e *flowsEnv) openChallenges(t *testing.T, f flow.NewFlow, cs ...flow.NewChallengeRecord) {
	t.Helper()
	e.locked(t, f, func(ctx context.Context, _ flow.Flow) error {
		for _, c := range cs {
			if err := e.flows.OpenChallenge(ctx, c); err != nil {
				return err
			}
		}
		return nil
	})
}

// withChallenges runs fn in one transaction holding the account, flow and challenge locks.
func (e *flowsEnv) withChallenges(t *testing.T, f flow.NewFlow, fn func(ctx context.Context, cs []flow.ChallengeRecord) error) error {
	t.Helper()
	found, err := e.flows.Find(t.Context(), f.ID, f.HandleHash)
	if err != nil {
		return err
	}
	return e.uow.Do(t.Context(), func(ctx context.Context) error {
		if _, err := e.repo.GetForUpdate(ctx, found.AccountID); err != nil {
			return err
		}
		if _, err := e.flows.LockFlow(ctx, found); err != nil {
			return err
		}
		cs, err := e.flows.LockChallenges(ctx, found.ID)
		if err != nil {
			return err
		}
		return fn(ctx, cs)
	})
}

// challengeTimes ignores the times the database sets.
var challengeTimes = cmpopts.IgnoreFields(flow.ChallengeRecord{}, "CreatedAt")

func TestChallengeRoundTrip(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	idID, email := e.identifierOf(t, acc)
	f := e.newFlow(acc, flow.KindRegistration, handle("a"))
	e.open(t, f)
	otp := e.otpChallenge(f.ID, idID, email, "123456")
	link := e.linkChallenge(f.ID, "new@example.org", "link-token")
	e.openChallenges(t, f, otp, link)

	want := []flow.ChallengeRecord{
		{ID: otp.ID, FlowID: f.ID, Purpose: otp.Purpose, Method: otp.Method, IdentifierID: &idID, SecretMAC: otp.SecretMAC,
			Challenge: flow.Challenge{MaxAttempts: 3, ExpiresAt: otp.ExpiresAt}},
		{ID: link.ID, FlowID: f.ID, Purpose: link.Purpose, Method: link.Method, SecretMAC: link.SecretMAC,
			Challenge: flow.Challenge{MaxAttempts: 1, ExpiresAt: link.ExpiresAt}},
	}
	err := e.withChallenges(t, f, func(ctx context.Context, cs []flow.ChallengeRecord) error {
		if d := cmp.Diff(want, cs, challengeTimes); d != "" {
			t.Errorf("LockChallenges (-want +got):\n%s", d)
		}
		for _, c := range []flow.NewChallengeRecord{otp, link} {
			secret, err := e.flows.ChallengeSecret(ctx, c.ID)
			if err != nil || !bytes.Equal(secret, c.Secret) {
				t.Errorf("ChallengeSecret(%s) = %v", c.Method, err)
			}
		}
		if v, err := e.flows.ChallengeTarget(ctx, link.ID); err != nil || v != "new@example.org" {
			t.Errorf("ChallengeTarget(link) = %q, %v", v, err)
		}
		_, err := e.flows.ChallengeTarget(ctx, otp.ID)
		checkCode(t, err, domain.CodeNotFound)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestFlowsStoreNoPlaintext reads raw rows: the secrets, the value under change and the pending
// secret are stored encrypted, bound to their place, and target_bidx is the blind index.
func TestFlowsStoreNoPlaintext(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	idID, email := e.identifierOf(t, acc)
	f := e.newFlow(acc, flow.KindTOTPReplacement, handle("a"))
	f.PendingSecret = flow.Secret("PENDINGTOTPSECRET")
	e.open(t, f)
	otp := e.otpChallenge(f.ID, idID, email, "918273")
	link := e.linkChallenge(f.ID, "changed@example.org", "the-link-token")
	e.openChallenges(t, f, otp, link)

	var pending []byte
	if err := e.su.QueryRowContext(t.Context(), "SELECT pending_secret FROM flows WHERE id = ?", f.ID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if len(pending) == 0 || bytes.Contains(pending, f.PendingSecret) {
		t.Errorf("pending_secret stored as plaintext or empty")
	}
	for _, c := range []flow.NewChallengeRecord{otp, link} {
		var secret, target, bidx []byte
		if err := e.su.QueryRowContext(t.Context(), "SELECT secret, target_value, target_bidx FROM challenges WHERE id = ?",
			c.ID).Scan(&secret, &target, &bidx); err != nil {
			t.Fatal(err)
		}
		if len(secret) == 0 || bytes.Contains(secret, c.Secret) {
			t.Errorf("%s: secret stored as plaintext or empty", c.Method)
		}
		if bytes.Contains(target, []byte(c.TargetValue)) || bytes.Contains(target, []byte("changed")) {
			t.Errorf("%s: target_value holds the plaintext", c.Method)
		}
		if (c.IdentifierID == nil) != (len(target) > 0) {
			t.Errorf("%s: target_value stored %v, want only without an identifier", c.Method, len(target) > 0)
		}
		want, err := e.bidx.Compute("email", []byte(c.TargetValue))
		if err != nil || !bytes.Equal(bidx, want) {
			t.Errorf("%s: target_bidx is not the blind index (%v)", c.Method, err)
		}
	}

	// A ciphertext moved to another row does not open there.
	e.exec(t, "UPDATE challenges SET secret = (SELECT secret FROM challenges WHERE id = ?) WHERE id = ?", link.ID, otp.ID)
	err := e.withChallenges(t, f, func(ctx context.Context, _ []flow.ChallengeRecord) error {
		_, err := e.flows.ChallengeSecret(ctx, otp.ID)
		return err
	})
	if !errors.Is(err, app.ErrCiphertextInvalid) {
		t.Errorf("moved secret: %v, want ErrCiphertextInvalid", err)
	}
}

// TestFindLink checks the link lookup: an open email_link challenge in a live flow, and nothing
// else, answered as the flow finders answer a miss.
func TestFindLink(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	idID, email := e.identifierOf(t, acc)
	f := e.newFlow(acc, flow.KindEmailChange, handle("a"))
	f.State = flow.EmailChangeState{ConfirmOld: flow.ConfirmOldNotify}
	e.open(t, f)
	link := e.linkChallenge(f.ID, "new@example.org", "token-live")
	expiredLink := e.linkChallenge(f.ID, "new@example.org", "token-expired")
	closedLink := e.linkChallenge(f.ID, "new@example.org", "token-closed")
	code := e.otpChallenge(f.ID, idID, email, "111111")
	code.SecretMAC = crypto.SHA256([]byte("token-code")) // a code's MAC equal to a link hash
	e.openChallenges(t, f, link, expiredLink, closedLink, code)
	e.exec(t, "UPDATE challenges SET expires_at = now() - interval '1 second' WHERE id = ?", expiredLink.ID)
	e.exec(t, "UPDATE challenges SET closed_at = now(), secret = NULL WHERE id = ?", closedLink.ID)

	gotFlow, gotChallenge, err := e.flows.FindLink(t.Context(), crypto.SHA256([]byte("token-live")))
	if err != nil {
		t.Fatal(err)
	}
	if gotFlow.ID != f.ID || gotFlow.AccountID != acc || gotChallenge.ID != link.ID || gotChallenge.FlowID != f.ID {
		t.Errorf("FindLink = flow %v, challenge %v", gotFlow.ID, gotChallenge.ID)
	}

	want := &domain.Error{Code: domain.CodeChallengeClosed, Detail: "the challenge is closed"}
	miss := func(name, token string) {
		t.Helper()
		_, _, err := e.flows.FindLink(t.Context(), crypto.SHA256([]byte(token)))
		var de *domain.Error
		if !errors.As(err, &de) || cmp.Diff(want, de) != "" {
			t.Errorf("%s: error = %v, want %v", name, err, want)
		}
	}
	miss("unknown token", "token-unknown")
	miss("expired challenge", "token-expired")
	miss("closed challenge", "token-closed")
	miss("not a link", "token-code")
	e.exec(t, "UPDATE flows SET expires_at = now() - interval '1 second' WHERE id = ?", f.ID)
	miss("expired flow", "token-live")
	e.exec(t, "UPDATE flows SET expires_at = now() + interval '1 hour', cancelled_at = now(), close_reason = 'replaced' WHERE id = ?", f.ID)
	miss("closed flow", "token-live")
}

// TestFlowsNoBulkDecrypt checks that lookups and challenge loads decrypt nothing, and reads
// decrypt only the one field they return (TDD-01 §6).
func TestFlowsNoBulkDecrypt(t *testing.T) {
	t.Parallel()
	counter := &countingCrypto{}
	e := flowsDBWith(t, func(fc app.FieldCrypto) app.FieldCrypto {
		counter.FieldCrypto = fc
		return counter
	})
	acc := e.flowAccount(t)
	idID, email := e.identifierOf(t, acc)
	f := e.newFlow(acc, flow.KindEmailChange, handle("a"))
	f.State = flow.EmailChangeState{ConfirmOld: flow.ConfirmOldNotify}
	e.open(t, f)
	var cs []flow.NewChallengeRecord
	for i := range 4 {
		cs = append(cs, e.otpChallenge(f.ID, idID, email, "00000"+string(rune('0'+i))))
	}
	link := e.linkChallenge(f.ID, "new@example.org", "token")
	e.openChallenges(t, f, append(cs, link)...)

	count := func(name string, want int64, call func() error) {
		t.Helper()
		before := counter.opens.Load()
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := counter.opens.Load() - before; got != want {
			t.Errorf("%s opened %d fields, want %d", name, got, want)
		}
	}
	count("Find", 0, func() error { _, err := e.flows.Find(t.Context(), f.ID, f.HandleHash); return err })
	count("FindByHandle", 0, func() error { _, err := e.flows.FindByHandle(t.Context(), f.HandleHash); return err })
	count("FindLink", 0, func() error {
		_, _, err := e.flows.FindLink(t.Context(), crypto.SHA256([]byte("token")))
		return err
	})
	count("LockFlow and LockChallenges of 5", 0, func() error {
		return e.withChallenges(t, f, func(context.Context, []flow.ChallengeRecord) error { return nil })
	})
	count("ChallengeSecret", 1, func() error {
		return e.withChallenges(t, f, func(ctx context.Context, _ []flow.ChallengeRecord) error {
			_, err := e.flows.ChallengeSecret(ctx, link.ID)
			return err
		})
	})
	count("ChallengeTarget", 1, func() error {
		return e.withChallenges(t, f, func(ctx context.Context, _ []flow.ChallengeRecord) error {
			_, err := e.flows.ChallengeTarget(ctx, link.ID)
			return err
		})
	})
}

// TestChallengeLockOrder checks that the challenge methods refuse to run without the flow's or
// the challenge's lock, or outside a transaction, before they query (G-5).
func TestChallengeLockOrder(t *testing.T) {
	t.Parallel()
	e := flowsDB(t)
	acc := e.flowAccount(t)
	idID, email := e.identifierOf(t, acc)
	f := e.newFlow(acc, flow.KindRegistration, handle("a"))
	e.open(t, f)
	c := e.otpChallenge(f.ID, idID, email, "123456")
	e.openChallenges(t, f, c)

	calls := map[string]func(ctx context.Context) error{
		"LockChallenges": func(ctx context.Context) error { _, err := e.flows.LockChallenges(ctx, f.ID); return err },
		"OpenChallenge": func(ctx context.Context) error {
			return e.flows.OpenChallenge(ctx, e.otpChallenge(f.ID, idID, email, "654321"))
		},
		"ChallengeSecret": func(ctx context.Context) error { _, err := e.flows.ChallengeSecret(ctx, c.ID); return err },
		"ChallengeTarget": func(ctx context.Context) error { _, err := e.flows.ChallengeTarget(ctx, c.ID); return err },
		"Attempt":         func(ctx context.Context) error { _, _, err := e.flows.Attempt(ctx, c.ID); return err },
		"RecordSend":      func(ctx context.Context) error { _, err := e.flows.RecordSend(ctx, c.ID); return err },
		"CloseChallenge":  func(ctx context.Context) error { _, err := e.flows.CloseChallenge(ctx, c.ID, true); return err },
	}
	// The flow locked, its challenges not loaded: only the flow-level ones may run.
	flowLevel := map[string]bool{"LockChallenges": true, "OpenChallenge": true}
	for name, call := range calls {
		if err := call(t.Context()); !errors.Is(err, postgres.ErrNoTransaction) {
			t.Errorf("%s outside a transaction: %v, want ErrNoTransaction", name, err)
		}
		if err := e.uow.Do(t.Context(), func(ctx context.Context) error {
			if _, err := e.repo.GetForUpdate(ctx, acc); err != nil {
				return err
			}
			return call(ctx)
		}); !errors.Is(err, postgres.ErrLockOrder) {
			t.Errorf("%s with the account locked only: %v, want ErrLockOrder", name, err)
		}
		found, err := e.flows.Find(t.Context(), f.ID, f.HandleHash)
		if err != nil {
			t.Fatal(err)
		}
		err = e.uow.Do(t.Context(), func(ctx context.Context) error {
			if _, err := e.repo.GetForUpdate(ctx, acc); err != nil {
				return err
			}
			if _, err := e.flows.LockFlow(ctx, found); err != nil {
				return err
			}
			if err := call(ctx); err != nil {
				return err
			}
			return errors.New("roll back")
		})
		if flowLevel[name] {
			if err == nil || err.Error() != "roll back" {
				t.Errorf("%s with the flow locked: %v", name, err)
			}
		} else if !errors.Is(err, postgres.ErrLockOrder) {
			t.Errorf("%s with the flow locked only: %v, want ErrLockOrder", name, err)
		}
	}
}
