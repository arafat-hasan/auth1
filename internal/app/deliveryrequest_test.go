package app_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

var (
	challengeID  = fakes.ID(1)
	identifierID = fakes.ID(2)
	expiresAt    = time.Date(2026, 10, 26, 10, 5, 0, 0, time.UTC)
)

func newMessages(t *testing.T, overrides map[string]string) *app.Messages {
	t.Helper()
	types, errs := message.NewTypes(overrides)
	if errs != nil {
		t.Fatalf("NewTypes = %v", errs)
	}
	return app.NewMessages(types)
}

func TestReferences(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b")
	got := []string{app.IdentifierRef(id), app.ChallengeTargetRef(id), app.SecretRef(id), app.LinkRef(id)}
	want := []string{
		"auth1:identifier:0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b",
		"auth1:challenge-target:0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b",
		"auth1:secret:0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b",
		"auth1:link:0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("references (-want +got):\n%s", diff)
	}
}

func TestChallengeCode(t *testing.T) {
	t.Parallel()
	m := newMessages(t, nil)
	c := app.Challenge{ID: challengeID, Send: 2, ExpiresAt: expiresAt.In(time.FixedZone("x", 3600))}
	got, err := m.ChallengeCode(message.PhoneVerificationCode, c, "en", app.ToIdentifier(identifierID, message.SMS))
	if err != nil {
		t.Fatalf("ChallengeCode = %v", err)
	}
	want := app.DeliveryRequest{
		RequestID: challengeID.String() + ":2",
		Type:      "auth.phone_verification_code",
		Channel:   "sms",
		Locale:    "en",
		Recipient: app.IdentifierRef(identifierID),
		Variables: map[string]any{"code": app.SecretRef(challengeID)},
		Deadline:  &expiresAt,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ChallengeCode (-want +got):\n%s", diff)
	}
	if got.Deadline.Location() != time.UTC {
		t.Errorf("deadline in %s, want UTC", got.Deadline.Location())
	}
}

func TestChallengeCodeTakesRecipientChannel(t *testing.T) {
	t.Parallel()
	m := newMessages(t, nil)
	c := app.Challenge{ID: challengeID, Send: 1, ExpiresAt: expiresAt}
	got, err := m.ChallengeCode(message.SignInCode, c, "en", app.ToIdentifier(identifierID, message.Email))
	if err != nil {
		t.Fatalf("ChallengeCode = %v", err)
	}
	if got.Channel != "email" || got.Type != "auth.sign_in_code" {
		t.Errorf("sign-in code: channel %q, type %q; want email, auth.sign_in_code", got.Channel, got.Type)
	}
}

func TestChallengeLink(t *testing.T) {
	t.Parallel()
	m := newMessages(t, map[string]string{"email_change_confirm_new": "x.email_change"})
	c := app.Challenge{ID: challengeID, Send: 1, ExpiresAt: expiresAt}
	got, err := m.ChallengeLink(message.EmailChangeConfirmNew, c, "en-GB", app.ToChallengeTarget(challengeID, ""))
	if err != nil {
		t.Fatalf("ChallengeLink = %v", err)
	}
	want := app.DeliveryRequest{
		RequestID: challengeID.String() + ":1",
		Type:      "x.email_change",
		Channel:   "email",
		Locale:    "en-GB",
		Recipient: app.ChallengeTargetRef(challengeID),
		Variables: map[string]any{"link": app.LinkRef(challengeID)},
		Deadline:  &expiresAt,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ChallengeLink (-want +got):\n%s", diff)
	}
}

func TestNotice(t *testing.T) {
	t.Parallel()
	m := newMessages(t, nil)
	vars := map[string]any{"change": "used", "remaining_codes": 3}
	got, err := m.Notice(message.NoticeRecoveryCodes, "en", app.ToIdentifier(identifierID, message.Email), vars)
	if err != nil {
		t.Fatalf("Notice = %v", err)
	}
	want := app.DeliveryRequest{
		Type:      "auth.notice_recovery_codes",
		Channel:   "email",
		Locale:    "en",
		Recipient: app.IdentifierRef(identifierID),
		Variables: map[string]any{"change": "used", "remaining_codes": 3},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Notice (-want +got):\n%s", diff)
	}
	vars["change"] = "changed after"
	if got.Variables["change"] != "used" {
		t.Error("Notice keeps the caller's map; want a copy")
	}
}

// TestNoticeToPhone: with no email type, a notice goes to the recipient's channel.
func TestNoticeToPhone(t *testing.T) {
	t.Parallel()
	m := newMessages(t, nil)
	vars := map[string]any{"change": "enrolled", "occurred_at": "2026-10-30T12:00:00Z"}
	got, err := m.Notice(message.NoticeMFAChanged, "en", app.ToIdentifier(identifierID, message.SMS), vars)
	if err != nil {
		t.Fatalf("Notice = %v", err)
	}
	if got.Channel != "sms" {
		t.Errorf("notice to a phone: channel %q, want sms", got.Channel)
	}
}

func TestBuildersRefuse(t *testing.T) {
	t.Parallel()
	m := newMessages(t, nil)
	c := app.Challenge{ID: challengeID, Send: 1, ExpiresAt: expiresAt}
	email := app.ToIdentifier(identifierID, message.Email)
	sms := app.ToIdentifier(identifierID, message.SMS)
	// notice builds the recovery-codes notice with valid variables changed by vars; a nil value in
	// vars is kept, and the key "-" removes the variable it names.
	notice := func(vars map[string]any) func() error {
		return func() error {
			all := map[string]any{"change": "used", "remaining_codes": 3}
			for k, v := range vars {
				if k == "-" {
					delete(all, v.(string))
					continue
				}
				all[k] = v
			}
			_, err := m.Notice(message.NoticeRecoveryCodes, "en", email, all)
			return err
		}
	}
	tests := map[string]func() error{
		"code for a link purpose": func() error {
			_, err := m.ChallengeCode(message.PasswordResetLink, c, "en", email)
			return err
		},
		"link for a code purpose": func() error {
			_, err := m.ChallengeLink(message.PhoneVerificationCode, c, "en", sms)
			return err
		},
		"code for a notice": func() error {
			_, err := m.ChallengeCode(message.NoticeMFAChanged, c, "en", email)
			return err
		},
		"unknown purpose": func() error {
			_, err := m.ChallengeCode("nope", c, "en", email)
			return err
		},
		"channel mismatch": func() error {
			_, err := m.ChallengeCode(message.PhoneVerificationCode, c, "en", email)
			return err
		},
		"no channel": func() error {
			_, err := m.ChallengeCode(message.SignInCode, c, "en", app.ToIdentifier(identifierID, ""))
			return err
		},
		"no recipient": func() error {
			_, err := m.ChallengeCode(message.PhoneVerificationCode, c, "en", app.Recipient{Channel: message.SMS})
			return err
		},
		"no locale": func() error {
			_, err := m.ChallengeCode(message.PhoneVerificationCode, c, "", sms)
			return err
		},
		"send 0": func() error {
			_, err := m.ChallengeCode(message.PhoneVerificationCode, app.Challenge{ID: challengeID, ExpiresAt: expiresAt}, "en", sms)
			return err
		},
		"no challenge id": func() error {
			_, err := m.ChallengeCode(message.PhoneVerificationCode, app.Challenge{Send: 1, ExpiresAt: expiresAt}, "en", sms)
			return err
		},
		"no expiry": func() error {
			_, err := m.ChallengeCode(message.PhoneVerificationCode, app.Challenge{ID: challengeID, Send: 1}, "en", sms)
			return err
		},
		"link by sms": func() error {
			_, err := m.ChallengeLink(message.RegistrationResume, c, "en", sms)
			return err
		},
		"recipient a secret reference": func() error {
			_, err := m.ChallengeCode(message.PhoneVerificationCode, c, "en",
				app.Recipient{Ref: app.SecretRef(challengeID), Channel: message.SMS})
			return err
		},
		"no message types": func() error {
			_, err := app.NewMessages(nil).ChallengeCode(message.PhoneVerificationCode, c, "en", sms)
			return err
		},
		"notice for a challenge purpose": func() error {
			_, err := m.Notice(message.PasswordResetLink, "en", email, nil)
			return err
		},
		"missing variable":   notice(map[string]any{"-": "change"}),
		"unknown variable":   notice(map[string]any{"code": "x"}),
		"float variable":     notice(map[string]any{"remaining_codes": 3.5}),
		"bool variable":      notice(map[string]any{"change": true}),
		"nil variable":       notice(map[string]any{"change": nil}),
		"map variable":       notice(map[string]any{"change": map[string]any{"a": "b"}}),
		"reference in plain": notice(map[string]any{"change": "auth1:identifier:" + identifierID.String()}),
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := build()
			if !errors.Is(err, app.ErrMessageInvalid) {
				t.Errorf("err = %v, want ErrMessageInvalid", err)
			}
		})
	}
}

// TestBuilderErrorsHoldNoValue: a refusal names the purpose and the variable, never the value (G-6).
func TestBuilderErrorsHoldNoValue(t *testing.T) {
	t.Parallel()
	m := newMessages(t, nil)
	value := "auth1:identifier:" + identifierID.String()
	_, err := m.Notice(message.NoticeRecoveryCodes, "en", app.ToIdentifier(identifierID, message.Email),
		map[string]any{"change": value, "remaining_codes": 3})
	if err == nil || strings.Contains(err.Error(), value) {
		t.Errorf("err = %v; want a refusal without the value", err)
	}
}
