package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/identifier"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// recordingOutbox keeps the delivery requests written to it.
type recordingOutbox struct {
	app.OutboxWriter
	accounts []uuid.UUID
	requests []app.DeliveryRequest
}

func (o *recordingOutbox) Delivery(_ context.Context, accountID uuid.UUID, req app.DeliveryRequest) error {
	o.accounts = append(o.accounts, accountID)
	o.requests = append(o.requests, req)
	return nil
}

// identifierStore answers Identifiers with the current identifiers it holds.
type identifierStore struct {
	app.Accounts
	ids []account.Identifier
}

func (s *identifierStore) Identifiers(_ context.Context, accountID uuid.UUID) ([]account.Identifier, error) {
	var out []account.Identifier
	for _, id := range s.ids {
		if id.AccountID == accountID && id.RetiredAt == nil {
			out = append(out, id)
		}
	}
	return out, nil
}

var (
	now       = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	accountID = fakes.ID(10)
	acct      = account.Account{ID: accountID, Locale: "en-GB"}
	emailPol  = identifier.Policy{Required: true, Verify: flow.MethodEmailLink, SignIn: true}
	phonePol  = identifier.Policy{Verify: flow.MethodSMSOTP, CallingCodes: []string{"44"}}
)

const window = 168 * time.Hour

func ident(n int, typ string, verified bool, retired *time.Time) account.Identifier {
	id := account.Identifier{ID: fakes.ID(n), AccountID: accountID, Type: typ, Value: "v", RetiredAt: retired}
	if verified {
		v := now.Add(-30 * 24 * time.Hour)
		id.VerifiedAt = &v
	}
	return id
}

type noticesEnv struct {
	notices *app.Notices
	outbox  *recordingOutbox
	clock   *fakes.Clock
}

func newNotices(t *testing.T, policies map[string]identifier.Policy, newSignIn bool, ids ...account.Identifier) *noticesEnv {
	t.Helper()
	reg, err := identifier.NewRegistry(identifier.Builtin(), policies)
	if err != nil {
		t.Fatal(err)
	}
	e := &noticesEnv{outbox: &recordingOutbox{}, clock: fakes.NewClock(now)}
	e.notices = app.NewNotices(&identifierStore{ids: ids}, e.outbox, newMessages(t, nil), reg, e.clock,
		app.NoticeOptions{RetiredAddressWindow: window, NewSignIn: newSignIn})
	return e
}

// recipients returns the recipient and channel of each request written.
func (e *noticesEnv) recipients() []string {
	var out []string
	for _, r := range e.outbox.requests {
		out = append(out, r.Channel+" "+r.Recipient)
	}
	return out
}

func send(t *testing.T, e *noticesEnv, n app.Notice) {
	t.Helper()
	if err := e.notices.Send(t.Context(), acct, n); err != nil {
		t.Fatalf("Send = %v", err)
	}
}

var mfaChanged = app.Notice{Purpose: message.NoticeMFAChanged, Variables: map[string]any{"change": "enrolled"}}

func TestNoticeDefaultRecipient(t *testing.T) {
	t.Parallel()
	both := map[string]identifier.Policy{"email": emailPol, "phone": phonePol}
	e := newNotices(t, both, false, ident(1, "phone", true, nil), ident(2, "email", true, nil))
	send(t, e, mfaChanged)
	want := []string{"email " + app.IdentifierRef(fakes.ID(2))}
	if diff := cmp.Diff(want, e.recipients()); diff != "" {
		t.Errorf("recipients (-want +got):\n%s", diff)
	}
}

func TestNoticeRow(t *testing.T) {
	t.Parallel()
	e := newNotices(t, map[string]identifier.Policy{"email": emailPol}, false, ident(2, "email", true, nil))
	send(t, e, mfaChanged)
	want := []app.DeliveryRequest{{
		Type: "auth.notice_mfa_changed", Channel: "email", Locale: "en-GB",
		Recipient: app.IdentifierRef(fakes.ID(2)), Variables: map[string]any{"change": "enrolled"},
	}}
	if diff := cmp.Diff(want, e.outbox.requests); diff != "" {
		t.Errorf("requests (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]uuid.UUID{accountID}, e.outbox.accounts); diff != "" {
		t.Errorf("row subjects (-want +got):\n%s", diff)
	}
}

// TestNoticeNoEmailType: with no email type, the notice goes to the first verified identifier by
// type name, by its type's channel.
func TestNoticeNoEmailType(t *testing.T) {
	t.Parallel()
	e := newNotices(t, map[string]identifier.Policy{"phone": phonePol}, false, ident(1, "phone", true, nil))
	send(t, e, mfaChanged)
	want := []string{"sms " + app.IdentifierRef(fakes.ID(1))}
	if diff := cmp.Diff(want, e.recipients()); diff != "" {
		t.Errorf("recipients (-want +got):\n%s", diff)
	}
}

// TestNoticeUnverifiedEmailSkipped: an unverified address gets no notice, and with an email type
// the phone is not used instead. No row, no error.
func TestNoticeUnverifiedEmailSkipped(t *testing.T) {
	t.Parallel()
	both := map[string]identifier.Policy{"email": emailPol, "phone": phonePol}
	e := newNotices(t, both, false, ident(1, "phone", true, nil), ident(2, "email", false, nil))
	send(t, e, mfaChanged)
	if len(e.outbox.requests) != 0 {
		t.Errorf("requests = %v, want none", e.outbox.requests)
	}
	e = newNotices(t, map[string]identifier.Policy{"phone": phonePol}, false, ident(1, "phone", false, nil))
	send(t, e, mfaChanged)
	if len(e.outbox.requests) != 0 {
		t.Errorf("no email type, unverified phone: requests = %v, want none", e.outbox.requests)
	}
}

// TestNoticeRetiredWindow: an explicit recipient retired less than the window ago still gets the
// notice; at the window and after, it does not.
func TestNoticeRetiredWindow(t *testing.T) {
	t.Parallel()
	email := map[string]identifier.Policy{"email": emailPol}
	tests := []struct {
		name    string
		retired time.Time
		want    bool
	}{
		{"just retired", now, true},
		{"1s inside the window", now.Add(-window + time.Second), true},
		{"at the window", now.Add(-window), false},
		{"after the window", now.Add(-window - time.Hour), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			old := ident(3, "email", true, &tt.retired)
			e := newNotices(t, email, false, old, ident(2, "email", true, nil))
			send(t, e, app.Notice{Purpose: message.NoticeIdentifierChanged, To: &old,
				Variables: map[string]any{"type": "email"}})
			var want []string
			if tt.want {
				want = []string{"email " + app.IdentifierRef(old.ID)}
			}
			if diff := cmp.Diff(want, e.recipients()); diff != "" {
				t.Errorf("recipients (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNoticeExplicitCurrent(t *testing.T) {
	t.Parallel()
	old := ident(3, "email", true, nil)
	e := newNotices(t, map[string]identifier.Policy{"email": emailPol}, false, old)
	send(t, e, app.Notice{Purpose: message.NoticeEmailChangeRequested, To: &old})
	if diff := cmp.Diff([]string{"email " + app.IdentifierRef(old.ID)}, e.recipients()); diff != "" {
		t.Errorf("recipients (-want +got):\n%s", diff)
	}
}

func TestNoticeExplicitRefused(t *testing.T) {
	t.Parallel()
	other := ident(4, "email", true, nil)
	other.AccountID = fakes.ID(11)
	unverified := ident(5, "email", false, nil)
	unconfigured := ident(6, "phone", true, nil)
	for name, to := range map[string]account.Identifier{
		"another account's": other, "unverified": unverified, "type not configured": unconfigured,
	} {
		e := newNotices(t, map[string]identifier.Policy{"email": emailPol}, false)
		send(t, e, app.Notice{Purpose: message.NoticeEmailChangeRequested, To: &to})
		if len(e.outbox.requests) != 0 {
			t.Errorf("%s identifier: requests = %v, want none", name, e.outbox.requests)
		}
	}
}

func TestNewSignInGate(t *testing.T) {
	t.Parallel()
	n := app.Notice{Purpose: message.NoticeNewSignIn, Variables: map[string]any{"client_id": "web"}}
	for _, on := range []bool{false, true} {
		e := newNotices(t, map[string]identifier.Policy{"email": emailPol}, on, ident(2, "email", true, nil))
		send(t, e, n)
		if got := len(e.outbox.requests); got != map[bool]int{false: 0, true: 1}[on] {
			t.Errorf("new_sign_in %v: %d requests", on, got)
		}
	}
}

func TestNoticeRefusesChallengePurpose(t *testing.T) {
	t.Parallel()
	e := newNotices(t, map[string]identifier.Policy{"email": emailPol}, false, ident(2, "email", true, nil))
	if err := e.notices.Send(t.Context(), acct, app.Notice{Purpose: message.PasswordResetLink}); err == nil {
		t.Error("Send of a challenge purpose = nil, want an error")
	}
}
