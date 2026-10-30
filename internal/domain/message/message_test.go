package message

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestDefaultTypes pins the purpose table to TDD-06 §7: every purpose, every notice included, with
// its default type, channel, secret and variables.
func TestDefaultTypes(t *testing.T) {
	t.Parallel()
	want := map[Purpose]Spec{
		PhoneVerificationCode:      {"auth.phone_verification_code", SMS, Code, []string{"code"}},
		EmailVerificationLink:      {"auth.email_verification_link", Email, Link, []string{"link"}},
		RegistrationResume:         {"auth.registration_resume", "", CodeOrLink, []string{"code", "link"}},
		SignInCode:                 {"auth.sign_in_code", "", Code, []string{"code"}},
		PasswordResetLink:          {"auth.password_reset_link", Email, Link, []string{"link"}},
		PasswordResetCode:          {"auth.password_reset_code", SMS, Code, []string{"code"}},
		EmailChangeConfirmOld:      {"auth.email_change_confirm_old", Email, Link, []string{"link"}},
		EmailChangeConfirmNew:      {"auth.email_change_confirm_new", Email, Link, []string{"link"}},
		PhoneChangeCode:            {"auth.phone_change_code", SMS, Code, []string{"code"}},
		InvitationLink:             {"auth.invitation_link", Email, Link, []string{"link", "display_name"}},
		NoticePasswordChanged:      {"auth.notice_password_changed", Email, NoSecret, []string{"occurred_at", "how"}},
		NoticeEmailChangeRequested: {"auth.notice_email_change_requested", Email, NoSecret, []string{"occurred_at"}},
		NoticeIdentifierChanged:    {"auth.notice_identifier_changed", Email, NoSecret, []string{"type", "occurred_at"}},
		NoticeMFAChanged:           {"auth.notice_mfa_changed", Email, NoSecret, []string{"change", "occurred_at"}},
		NoticeRecoveryCodes:        {"auth.notice_recovery_codes", Email, NoSecret, []string{"change", "remaining_codes"}},
		NoticeSessionsRevoked:      {"auth.notice_sessions_revoked", Email, NoSecret, []string{"reason", "occurred_at"}},
		NoticeNewSignIn:            {"auth.notice_new_sign_in", Email, NoSecret, []string{"client_id", "user_agent", "occurred_at"}},
	}
	purposes := Purposes()
	if len(purposes) != len(want) {
		t.Fatalf("Purposes() has %d purposes, want %d", len(purposes), len(want))
	}
	types, errs := NewTypes(nil)
	if errs != nil {
		t.Fatalf("NewTypes(nil) = %v", errs)
	}
	for _, p := range purposes {
		spec, ok := SpecOf(p)
		if !ok {
			t.Errorf("SpecOf(%q) not found", p)
			continue
		}
		if diff := cmp.Diff(want[p], spec); diff != "" {
			t.Errorf("SpecOf(%q) (-want +got):\n%s", p, diff)
		}
		if got := "auth." + string(p); got != spec.DefaultType {
			t.Errorf("purpose %q: default type %q is not auth.<purpose>", p, spec.DefaultType)
		}
		if got := types.Type(p); got != spec.DefaultType {
			t.Errorf("Type(%q) = %q, want the default %q", p, got, spec.DefaultType)
		}
		if got, want := p.Notice(), spec.Secret == NoSecret; got != want {
			t.Errorf("%q.Notice() = %v, want %v", p, got, want)
		}
	}
	if _, ok := SpecOf("nope"); ok {
		t.Error(`SpecOf("nope") found a purpose`)
	}
}

func TestNewTypesOverride(t *testing.T) {
	t.Parallel()
	types, errs := NewTypes(map[string]string{"password_reset_link": "x.reset"})
	if errs != nil {
		t.Fatalf("NewTypes = %v", errs)
	}
	if got := types.Type(PasswordResetLink); got != "x.reset" {
		t.Errorf("Type(PasswordResetLink) = %q, want x.reset", got)
	}
	if got := types.Type(SignInCode); got != "auth.sign_in_code" {
		t.Errorf("Type(SignInCode) = %q, want the default", got)
	}
}

func TestNewTypesRefuses(t *testing.T) {
	t.Parallel()
	_, errs := NewTypes(map[string]string{"sign_in_code": "", "nope": "t", "phone_change_code": "ok"})
	var got []string
	for _, e := range errs {
		got = append(got, e.Error())
	}
	want := []string{
		"delivery.types.nope: unknown purpose",
		"delivery.types.sign_in_code: the message type is empty",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("NewTypes problems (-want +got):\n%s", diff)
	}
}
