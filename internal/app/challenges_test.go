package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// sendFlows records the challenges opened and the sends counted, and answers SendCounts with
// counts.
type sendFlows struct {
	app.Flows
	opened  []flow.NewChallengeRecord
	sends   map[uuid.UUID]int
	counts    app.SendCounts
	exhausted *time.Time // returned by ExhaustedSince
	within    []time.Duration
	windows   []app.SendWindows
	targets []string // type:value of each SendCounts call
}

func (f *sendFlows) OpenChallenge(_ context.Context, c flow.NewChallengeRecord) error {
	f.opened = append(f.opened, c)
	return nil
}

func (f *sendFlows) SendCounts(_ context.Context, targetType, value string, w app.SendWindows) (app.SendCounts, error) {
	f.windows = append(f.windows, w)
	f.targets = append(f.targets, targetType+":"+value)
	return f.counts, nil
}

func (f *sendFlows) ExhaustedSince(_ context.Context, _, _ string, within time.Duration) (*time.Time, error) {
	f.within = append(f.within, within)
	return f.exhausted, nil
}

func (f *sendFlows) RecordSend(_ context.Context, id uuid.UUID) (int, error) {
	if f.sends == nil {
		f.sends = map[uuid.UUID]int{}
	}
	f.sends[id]++
	return f.sends[id], nil
}

// testMAC is a MAC whose OTP is "otp|<challenge id>|<code>", so tests can see what it bound.
type testMAC struct{}

func (testMAC) OTP(id uuid.UUID, code []byte) []byte {
	return []byte("otp|" + id.String() + "|" + string(code))
}

func (testMAC) RecoveryCode(id uuid.UUID, code []byte) []byte {
	return []byte("rc|" + id.String() + "|" + string(code))
}

var challengeRules = app.ChallengeRules{
	OTPLength: 6, MaxAttempts: 3, OTPTTL: 5 * time.Minute, LinkTTL: 24 * time.Hour,
	Windows: app.SendWindows{Short: time.Minute, Long: time.Hour}, MaxShort: 1, MaxLong: 5, Cooldown: 15 * time.Minute,
}

type challengesEnv struct {
	c      *app.Challenges
	flows  *sendFlows
	outbox *recordingOutbox
}

func newChallengesEnv(t *testing.T) challengesEnv {
	t.Helper()
	types, errs := message.NewTypes(nil)
	if errs != nil {
		t.Fatal(errs)
	}
	e := challengesEnv{flows: &sendFlows{}, outbox: &recordingOutbox{}}
	// Every random byte is 7: codes are "777777" and tokens are fixed.
	rnd := bytes.NewReader(bytes.Repeat([]byte{7}, 4096))
	c, err := app.NewChallenges(e.flows, e.outbox, app.NewMessages(types), testMAC{}, fakes.NewIDs(), fakes.NewClock(now), rnd, challengeRules)
	if err != nil {
		t.Fatal(err)
	}
	e.c = c
	return e
}

var (
	flowID    = fakes.ID(20)
	emailID   = account.Identifier{ID: fakes.ID(11), AccountID: accountID, Type: "email", Value: "someone@example.com"}
	phoneID   = account.Identifier{ID: fakes.ID(12), AccountID: accountID, Type: "phone", Value: "+447400123456"}
	otpSecret = []byte("777777")
)

func TestOpenVerificationStoresMACNotSecret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		id     account.Identifier
		method flow.Method
		ttl    time.Duration
		mac    func(id uuid.UUID, secret []byte) []byte
	}{
		{"sms code", phoneID, flow.MethodSMSOTP, 5 * time.Minute, testMAC{}.OTP},
		{"email code", emailID, flow.MethodEmailCode, 5 * time.Minute, testMAC{}.OTP},
		{"email link", emailID, flow.MethodEmailLink, 24 * time.Hour, func(_ uuid.UUID, s []byte) []byte {
			h := sha256.Sum256(s)
			return h[:]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newChallengesEnv(t)
			got, err := e.c.OpenVerification(context.Background(), flowID, tt.id, tt.method)
			if err != nil {
				t.Fatal(err)
			}
			if len(e.flows.opened) != 1 {
				t.Fatalf("opened %d challenges; want 1", len(e.flows.opened))
			}
			nc := e.flows.opened[0]
			idID := tt.id.ID
			want := flow.NewChallengeRecord{
				ID: nc.ID, FlowID: flowID, Purpose: flow.PurposeVerifyIdentifier, Method: tt.method,
				IdentifierID: &idID, TargetType: tt.id.Type, TargetValue: tt.id.Value,
				SecretMAC: tt.mac(nc.ID, nc.Secret), Secret: nc.Secret, MaxAttempts: 3, ExpiresAt: now.Add(tt.ttl),
			}
			if diff := cmp.Diff(want, nc); diff != "" {
				t.Errorf("opened (-want +got):\n%s", diff)
			}
			if tt.method != flow.MethodEmailLink && !bytes.Equal(nc.Secret, otpSecret) {
				t.Errorf("code %q; want the 6 digits drawn", []byte(nc.Secret))
			}
			if tt.method == flow.MethodEmailLink && len(nc.Secret) != 43 {
				t.Errorf("token has %d characters; want 43", len(nc.Secret))
			}
			if got.ID != nc.ID || got.Method != tt.method || !got.ExpiresAt.Equal(nc.ExpiresAt) || got.MaxAttempts != 3 {
				t.Errorf("record = %+v; want the opened challenge", got)
			}
		})
	}
}

func TestChallengesSend(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		id      account.Identifier
		method  flow.Method
		channel message.Channel
		want    app.DeliveryRequest
	}{
		{"sms code", phoneID, flow.MethodSMSOTP, message.SMS, app.DeliveryRequest{
			Type: "auth.phone_verification_code", Channel: "sms", Variables: map[string]any{"code": "auth1:secret:"},
		}},
		{"email code", emailID, flow.MethodEmailCode, message.Email, app.DeliveryRequest{
			Type: "auth.email_verification_code", Channel: "email", Variables: map[string]any{"code": "auth1:secret:"},
		}},
		{"email link", emailID, flow.MethodEmailLink, message.Email, app.DeliveryRequest{
			Type: "auth.email_verification_link", Channel: "email", Variables: map[string]any{"link": "auth1:link:"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newChallengesEnv(t)
			ctx := context.Background()
			ch, err := e.c.OpenVerification(ctx, flowID, tt.id, tt.method)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := e.c.Send(ctx, acct, ch, tt.id, tt.channel); err != nil {
					t.Fatal(err)
				}
			}
			if !slices.Equal(e.flows.targets, []string{tt.id.Type + ":" + tt.id.Value, tt.id.Type + ":" + tt.id.Value}) {
				t.Errorf("send limits checked on %v; want the identifier's address", e.flows.targets)
			}
			if e.flows.windows[0] != challengeRules.Windows {
				t.Errorf("windows = %+v; want %+v", e.flows.windows[0], challengeRules.Windows)
			}
			if len(e.outbox.requests) != 2 {
				t.Fatalf("wrote %d requests; want 2", len(e.outbox.requests))
			}
			deadline := ch.ExpiresAt
			for i, got := range e.outbox.requests {
				want := tt.want
				want.RequestID = ch.ID.String() + ":" + string(rune('1'+i))
				want.Locale, want.Recipient, want.Deadline = acct.Locale, app.IdentifierRef(tt.id.ID), &deadline
				want.Variables = map[string]any{}
				for k, v := range tt.want.Variables {
					want.Variables[k] = v.(string) + ch.ID.String()
				}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("request %d (-want +got):\n%s", i, diff)
				}
				if e.outbox.accounts[i] != accountID {
					t.Errorf("request %d about %v; want the account", i, e.outbox.accounts[i])
				}
			}
		})
	}
}

func TestChallengesSendLimits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		counts app.SendCounts
		code   domain.Code
		retry  time.Duration
	}{
		{"one in the last minute", app.SendCounts{Short: 1, Long: 1}, domain.CodeResendTooSoon, time.Minute},
		{"five in the last hour", app.SendCounts{Short: 0, Long: 5}, domain.CodeRateLimited, time.Hour},
		{"both", app.SendCounts{Short: 1, Long: 5}, domain.CodeResendTooSoon, time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newChallengesEnv(t)
			ctx := context.Background()
			ch, err := e.c.OpenVerification(ctx, flowID, phoneID, flow.MethodSMSOTP)
			if err != nil {
				t.Fatal(err)
			}
			e.flows.counts = tt.counts
			err = e.c.Send(ctx, acct, ch, phoneID, message.SMS)
			var de *domain.Error
			if !errors.As(err, &de) || de.Code != tt.code || de.RetryAfter != tt.retry {
				t.Fatalf("Send = %v; want %s with retry %v", err, tt.code, tt.retry)
			}
			if len(e.flows.sends) != 0 || len(e.outbox.requests) != 0 {
				t.Errorf("a refused send recorded %v and wrote %d requests; want nothing", e.flows.sends, len(e.outbox.requests))
			}
		})
	}
}

func TestNewChallengesRefusesBadRules(t *testing.T) {
	t.Parallel()
	types, _ := message.NewTypes(nil)
	for name, edit := range map[string]func(*app.ChallengeRules){
		"no OTP lifetime":   func(r *app.ChallengeRules) { r.OTPTTL = 0 },
		"no link lifetime":  func(r *app.ChallengeRules) { r.LinkTTL = 0 },
		"short OTP":         func(r *app.ChallengeRules) { r.OTPLength = 5 },
		"no attempts":       func(r *app.ChallengeRules) { r.MaxAttempts = 0 },
		"no short window":   func(r *app.ChallengeRules) { r.Windows.Short = 0 },
		"short above long":  func(r *app.ChallengeRules) { r.Windows.Short = 2 * time.Hour },
		"no short sends":    func(r *app.ChallengeRules) { r.MaxShort = 0 },
		"long below short":  func(r *app.ChallengeRules) { r.MaxShort, r.MaxLong = 2, 1 },
		"negative cooldown": func(r *app.ChallengeRules) { r.Cooldown = -time.Second },
	} {
		r := challengeRules
		edit(&r)
		if _, err := app.NewChallenges(&sendFlows{}, &recordingOutbox{}, app.NewMessages(types), testMAC{},
			fakes.NewIDs(), fakes.NewClock(now), bytes.NewReader(nil), r); err == nil {
			t.Errorf("%s: NewChallenges accepted %+v", name, r)
		}
	}
}

// TestChallengesSendCooldown (L-9): after a challenge to an address ran out of attempts, no new
// send goes to that address, from any flow, until the cooldown has passed since it closed.
func TestChallengesSendCooldown(t *testing.T) {
	t.Parallel()
	e := newChallengesEnv(t)
	ctx := context.Background()
	ch, err := e.c.OpenVerification(ctx, flowID, phoneID, flow.MethodSMSOTP)
	if err != nil {
		t.Fatal(err)
	}
	closed := now.Add(-5 * time.Minute)
	e.flows.exhausted = &closed
	err = e.c.Send(ctx, acct, ch, phoneID, message.SMS)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeResendTooSoon || de.RetryAfter != 10*time.Minute {
		t.Fatalf("Send = %v; want RESEND_TOO_SOON with the 10 minutes left of the cooldown", err)
	}
	if len(e.flows.sends) != 0 || len(e.outbox.requests) != 0 {
		t.Error("a send in the cooldown was recorded or written")
	}
	if !slices.Equal(e.flows.within, []time.Duration{15 * time.Minute}) {
		t.Errorf("ExhaustedSince within %v; want the cooldown", e.flows.within)
	}

	e.flows.exhausted = nil
	if err := e.c.Send(ctx, acct, ch, phoneID, message.SMS); err != nil {
		t.Errorf("Send after the cooldown: %v", err)
	}
}
