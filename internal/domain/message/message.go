package message

import (
	"maps"
	"slices"
)

// Purpose is why a message is sent. Its value is the key of delivery.types and the default
// type's name without "auth.".
type Purpose string

// The purposes of TDD-06 §7.
const (
	PhoneVerificationCode      Purpose = "phone_verification_code"
	EmailVerificationLink      Purpose = "email_verification_link"
	RegistrationResume         Purpose = "registration_resume"
	SignInCode                 Purpose = "sign_in_code"
	PasswordResetLink          Purpose = "password_reset_link"
	PasswordResetCode          Purpose = "password_reset_code"
	EmailChangeConfirmOld      Purpose = "email_change_confirm_old"
	EmailChangeConfirmNew      Purpose = "email_change_confirm_new"
	PhoneChangeCode            Purpose = "phone_change_code"
	InvitationLink             Purpose = "invitation_link"
	NoticePasswordChanged      Purpose = "notice_password_changed"
	NoticeEmailChangeRequested Purpose = "notice_email_change_requested"
	NoticeIdentifierChanged    Purpose = "notice_identifier_changed"
	NoticeMFAChanged           Purpose = "notice_mfa_changed"
	NoticeRecoveryCodes        Purpose = "notice_recovery_codes"
	NoticeSessionsRevoked      Purpose = "notice_sessions_revoked"
	NoticeNewSignIn            Purpose = "notice_new_sign_in"
)

// Channel is how a message reaches its recipient: the contract's DeliveryRequest channel.
type Channel string

// The channels.
const (
	Email Channel = "email"
	SMS   Channel = "sms"
)

// Secret is the secret a message carries, as a variable.
type Secret int

// The secrets. A message with NoSecret is a security notice.
const (
	NoSecret   Secret = iota
	Code              // an OTP, in the code variable
	Link              // a link with its token, in the link variable
	CodeOrLink        // either, by the identifier's verify method
)

// Spec is a purpose's row of TDD-06 §7.
type Spec struct {
	DefaultType string
	Channel     Channel // empty: the recipient's identifier type decides
	Secret      Secret
	Variables   []string // the variables the message may carry
}

// purposes is the table, in TDD-06 §7 order.
var purposes = []struct {
	purpose Purpose
	spec    Spec
}{
	{PhoneVerificationCode, Spec{"auth.phone_verification_code", SMS, Code, []string{"code"}}},
	{EmailVerificationLink, Spec{"auth.email_verification_link", Email, Link, []string{"link"}}},
	{RegistrationResume, Spec{"auth.registration_resume", "", CodeOrLink, []string{"code", "link"}}},
	{SignInCode, Spec{"auth.sign_in_code", "", Code, []string{"code"}}},
	{PasswordResetLink, Spec{"auth.password_reset_link", Email, Link, []string{"link"}}},
	{PasswordResetCode, Spec{"auth.password_reset_code", SMS, Code, []string{"code"}}},
	{EmailChangeConfirmOld, Spec{"auth.email_change_confirm_old", Email, Link, []string{"link"}}},
	{EmailChangeConfirmNew, Spec{"auth.email_change_confirm_new", Email, Link, []string{"link"}}},
	{PhoneChangeCode, Spec{"auth.phone_change_code", SMS, Code, []string{"code"}}},
	{InvitationLink, Spec{"auth.invitation_link", Email, Link, []string{"link", "display_name"}}},
	{NoticePasswordChanged, Spec{"auth.notice_password_changed", Email, NoSecret, []string{"occurred_at", "how"}}},
	{NoticeEmailChangeRequested, Spec{"auth.notice_email_change_requested", Email, NoSecret, []string{"occurred_at"}}},
	{NoticeIdentifierChanged, Spec{"auth.notice_identifier_changed", Email, NoSecret, []string{"type", "occurred_at"}}},
	{NoticeMFAChanged, Spec{"auth.notice_mfa_changed", Email, NoSecret, []string{"change", "occurred_at"}}},
	{NoticeRecoveryCodes, Spec{"auth.notice_recovery_codes", Email, NoSecret, []string{"change", "remaining_codes"}}},
	{NoticeSessionsRevoked, Spec{"auth.notice_sessions_revoked", Email, NoSecret, []string{"reason", "occurred_at"}}},
	{NoticeNewSignIn, Spec{"auth.notice_new_sign_in", Email, NoSecret, []string{"client_id", "user_agent", "occurred_at"}}},
}

// Purposes returns every purpose, in TDD-06 §7 order.
func Purposes() []Purpose {
	out := make([]Purpose, len(purposes))
	for i, p := range purposes {
		out[i] = p.purpose
	}
	return out
}

// SpecOf returns the purpose's row of TDD-06 §7.
func SpecOf(p Purpose) (Spec, bool) {
	for _, row := range purposes {
		if row.purpose == p {
			s := row.spec
			s.Variables = slices.Clone(s.Variables)
			return s, true
		}
	}
	return Spec{}, false
}

// Notice reports whether p is a security notice: a message that carries no secret.
func (p Purpose) Notice() bool {
	s, ok := SpecOf(p)
	return ok && s.Secret == NoSecret
}

// Types is the message type of each purpose: the default, or the delivery.types override. It is
// built once at start-up and only read after.
type Types struct {
	types map[Purpose]string
}

// NewTypes returns the table with overrides, delivery.types, applied. An override must name a
// known purpose and a non-empty type; the problems are returned as TypeErrors, sorted by purpose.
func NewTypes(overrides map[string]string) (*Types, TypeErrors) {
	t := &Types{types: make(map[Purpose]string, len(purposes))}
	for _, row := range purposes {
		t.types[row.purpose] = row.spec.DefaultType
	}
	var errs TypeErrors
	for _, key := range slices.Sorted(maps.Keys(overrides)) {
		p := Purpose(key)
		switch _, known := t.types[p]; {
		case !known:
			errs = append(errs, TypeError{Purpose: key, Message: "unknown purpose"})
		case overrides[key] == "":
			errs = append(errs, TypeError{Purpose: key, Message: "the message type is empty"})
		default:
			t.types[p] = overrides[key]
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return t, nil
}

// Type returns the message type of p; empty for an unknown purpose.
func (t *Types) Type(p Purpose) string { return t.types[p] }

// TypeError is a problem of delivery.types found at start-up.
type TypeError struct {
	Purpose string // the key as configured
	Message string
}

// Path returns "delivery.types.<purpose>".
func (e *TypeError) Path() string { return "delivery.types." + e.Purpose }

// Error returns "<path>: <message>".
func (e *TypeError) Error() string { return e.Path() + ": " + e.Message }

// TypeErrors is every problem NewTypes found.
type TypeErrors []TypeError
