package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

func TestOpenResume(t *testing.T) {
	t.Parallel()
	for _, m := range []flow.Method{flow.MethodEmailCode, flow.MethodEmailLink} {
		e := newChallengesEnv(t)
		got, err := e.c.OpenResume(context.Background(), flowID, emailID, m)
		if err != nil {
			t.Fatal(err)
		}
		nc := e.flows.opened[0]
		if nc.Purpose != flow.PurposeResume || got.Purpose != flow.PurposeResume || nc.Method != m || got.ID != nc.ID {
			t.Errorf("%s: opened %+v, returned %+v; want a resume challenge", m, nc, got)
		}
		if m == flow.MethodEmailCode && string(nc.SecretMAC) != string(testMAC{}.OTP(nc.ID, nc.Secret)) {
			t.Errorf("%s: the MAC is not bound to the challenge", m)
		}
	}
}

// resumeSends are n resume challenges by email code to one address, each of its own account
// holding it: newest first, as resume sends them.
func resumeSends(t *testing.T, e challengesEnv, n int) []app.Outgoing {
	t.Helper()
	var out []app.Outgoing
	for i := range n {
		a := account.Account{ID: fakes.ID(100 + i), Locale: "en-GB"}
		id := account.Identifier{ID: fakes.ID(200 + i), AccountID: a.ID, Type: "email", Value: emailID.Value}
		ch, err := e.c.OpenResume(context.Background(), fakes.ID(300+i), id, flow.MethodEmailCode)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, app.Outgoing{Account: a, Challenge: ch, IdentifierID: id.ID})
	}
	return out
}

// TestSendBatch: a resume request's messages to one value share one check of the limits (TDD-07
// §5): each is recorded and written, as the resume message, while the long window has room.
func TestSendBatch(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		counts app.SendCounts
		sent   int
	}{
		{"room for all", app.SendCounts{Long: 2}, 3},
		{"room for one", app.SendCounts{Long: 4}, 1},
	} {
		e := newChallengesEnv(t)
		out := resumeSends(t, e, 3)
		e.flows.counts = tt.counts
		n, err := e.c.SendBatch(context.Background(), "email", emailID.Value, message.Email, out)
		if err != nil || n != tt.sent {
			t.Fatalf("%s: SendBatch = %d, %v; want %d", tt.name, n, err, tt.sent)
		}
		if len(e.flows.targets) != 1 || len(e.flows.within) != 1 {
			t.Errorf("%s: limits checked %d times, cooldown %d; want once", tt.name, len(e.flows.targets), len(e.flows.within))
		}
		if len(e.outbox.requests) != tt.sent || len(e.flows.sends) != tt.sent {
			t.Fatalf("%s: wrote %d, recorded %d; want %d", tt.name, len(e.outbox.requests), len(e.flows.sends), tt.sent)
		}
		for i, req := range e.outbox.requests {
			o := out[i] // newest first: the first ones go
			deadline := o.Challenge.ExpiresAt
			want := app.DeliveryRequest{
				RequestID: o.Challenge.ID.String() + ":1", Type: "auth.registration_resume", Channel: "email",
				Locale: "en-GB", Recipient: app.IdentifierRef(o.IdentifierID),
				Variables: map[string]any{"code": "auth1:secret:" + o.Challenge.ID.String()}, Deadline: &deadline,
			}
			if d := cmp.Diff(want, req); d != "" {
				t.Errorf("%s: request %d (-want +got):\n%s", tt.name, i, d)
			}
			if e.outbox.accounts[i] != o.Account.ID {
				t.Errorf("%s: request %d about %v; want %v", tt.name, i, e.outbox.accounts[i], o.Account.ID)
			}
		}
	}
}

func TestSendBatchRefused(t *testing.T) {
	t.Parallel()
	closed := now.Add(-time.Minute)
	for _, tt := range []struct {
		name      string
		counts    app.SendCounts
		exhausted *time.Time
		code      domain.Code
	}{
		{"short window used", app.SendCounts{Short: 1, Long: 1}, nil, domain.CodeResendTooSoon},
		{"long window full", app.SendCounts{Long: 5}, nil, domain.CodeRateLimited},
		{"cooldown", app.SendCounts{}, &closed, domain.CodeResendTooSoon},
	} {
		e := newChallengesEnv(t)
		out := resumeSends(t, e, 3)
		e.flows.counts, e.flows.exhausted = tt.counts, tt.exhausted
		n, err := e.c.SendBatch(context.Background(), "email", emailID.Value, message.Email, out)
		var de *domain.Error
		if n != 0 || !errors.As(err, &de) || de.Code != tt.code {
			t.Errorf("%s: SendBatch = %d, %v; want 0, %s", tt.name, n, err, tt.code)
		}
		if len(e.flows.sends) != 0 || len(e.outbox.requests) != 0 {
			t.Errorf("%s: a refused batch recorded or wrote something", tt.name)
		}
	}
}

func TestSendBatchLinkAndNone(t *testing.T) {
	t.Parallel()
	e := newChallengesEnv(t)
	ctx := context.Background()
	ch, err := e.c.OpenResume(ctx, flowID, emailID, flow.MethodEmailLink)
	if err != nil {
		t.Fatal(err)
	}
	out := []app.Outgoing{{Account: acct, Challenge: ch, IdentifierID: emailID.ID}}
	if n, err := e.c.SendBatch(ctx, "email", emailID.Value, message.Email, out); n != 1 || err != nil {
		t.Fatalf("SendBatch = %d, %v", n, err)
	}
	req := e.outbox.requests[0]
	if req.Type != "auth.registration_resume" || req.Variables["link"] != "auth1:link:"+ch.ID.String() {
		t.Errorf("link request %+v; want the resume message with its link", req)
	}
	if n, err := e.c.SendBatch(ctx, "email", emailID.Value, message.Email, nil); n != 0 || err != nil {
		t.Errorf("empty batch = %d, %v", n, err)
	}
	// An empty batch does the same address lock and count as a real one, so a resume for an unknown
	// value takes as long as one for a known value (TDD-02 §4).
	if len(e.flows.targets) != 2 {
		t.Errorf("an empty batch did not check the limits")
	}
}
