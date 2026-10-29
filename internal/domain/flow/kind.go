package flow

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// Kind is a flow's kind (TDD-02 §2.1), the values of flows.kind.
type Kind string

// The flow kinds, in the order of the flows.kind CHECK.
const (
	KindRegistration    Kind = "registration"
	KindInvitation      Kind = "invitation"
	KindSignIn          Kind = "sign_in"
	KindPasswordReset   Kind = "password_reset"
	KindEmailChange     Kind = "email_change"
	KindPhoneChange     Kind = "phone_change"
	KindTOTPReplacement Kind = "totp_replacement"
)

var kinds = []Kind{KindRegistration, KindInvitation, KindSignIn, KindPasswordReset, KindEmailChange,
	KindPhoneChange, KindTOTPReplacement}

// Kinds returns every flow kind, in the order of the flows.kind CHECK.
func Kinds() []Kind { return slices.Clone(kinds) }

// ParseKind returns the kind named s, matched exactly. Any other value is VALIDATION_FAILED on the
// field "kind".
func ParseKind(s string) (Kind, error) { return parse(kinds, s, "kind") }

// Purpose is what a challenge proves (TDD-02 §2.3), the values of challenges.purpose.
type Purpose string

// The challenge purposes, in TDD-02 §2.3 order.
const (
	PurposeVerifyIdentifier Purpose = "verify_identifier"
	PurposeResume           Purpose = "resume"
	PurposeInvitation       Purpose = "invitation"
	PurposeSignIn           Purpose = "sign_in"
	PurposeResetLink        Purpose = "reset_link"
	PurposeResetStepUp      Purpose = "reset_step_up"
	PurposeEmailChangeOld   Purpose = "email_change_old"
	PurposeEmailChangeNew   Purpose = "email_change_new"
	PurposePhoneChange      Purpose = "phone_change"
)

var purposes = []Purpose{PurposeVerifyIdentifier, PurposeResume, PurposeInvitation, PurposeSignIn,
	PurposeResetLink, PurposeResetStepUp, PurposeEmailChangeOld, PurposeEmailChangeNew, PurposePhoneChange}

// Purposes returns every challenge purpose, in TDD-02 §2.3 order.
func Purposes() []Purpose { return slices.Clone(purposes) }

// ParsePurpose returns the purpose named s, matched exactly. Any other value is VALIDATION_FAILED
// on the field "purpose".
func ParsePurpose(s string) (Purpose, error) { return parse(purposes, s, "purpose") }

// Method is how a challenge's secret is sent (SDD D-4), the values of challenges.method.
type Method string

// The challenge methods, in the order of the challenges.method CHECK.
const (
	MethodSMSOTP    Method = "sms_otp"
	MethodEmailLink Method = "email_link"
	MethodEmailCode Method = "email_code"
)

var methods = []Method{MethodSMSOTP, MethodEmailLink, MethodEmailCode}

// Methods returns every challenge method, in the order of the challenges.method CHECK.
func Methods() []Method { return slices.Clone(methods) }

// ParseMethod returns the method named s, matched exactly. Any other value is VALIDATION_FAILED on
// the field "method".
func ParseMethod(s string) (Method, error) { return parse(methods, s, "method") }

// CloseReason is why a flow closed without completing, or was replaced (TDD-02 §2.1), the values
// of flows.close_reason.
type CloseReason string

// The flow close reasons, in TDD-02 §2.1 order.
const (
	CloseReplaced      CloseReason = "replaced"       // a flow of the same kind opened for the account
	CloseExpired       CloseReason = "expired"        // expires_at passed
	CloseAccountClosed CloseReason = "account_closed" // the account was deleted
	CloseAttempts      CloseReason = "attempts"       // too many wrong second-factor codes (TDD-03 §3.3)
)

var closeReasons = []CloseReason{CloseReplaced, CloseExpired, CloseAccountClosed, CloseAttempts}

// CloseReasons returns every close reason, in TDD-02 §2.1 order.
func CloseReasons() []CloseReason { return slices.Clone(closeReasons) }

// ParseCloseReason returns the close reason named s, matched exactly. Any other value is
// VALIDATION_FAILED on the field "close_reason".
func ParseCloseReason(s string) (CloseReason, error) { return parse(closeReasons, s, "close_reason") }

// parse returns s as a member of values, or VALIDATION_FAILED naming field.
func parse[T ~string](values []T, s, field string) (T, error) {
	if slices.Contains(values, T(s)) {
		return T(s), nil
	}
	return "", &domain.Error{
		Code:   domain.CodeValidationFailed,
		Detail: "the request has invalid fields",
		Fields: []domain.FieldError{{Field: field, Code: domain.FieldUnknown}},
	}
}

// Lifetimes is how long a flow of each kind stays open (TDD-02 §2.1), from configuration.
type Lifetimes struct {
	Registration    time.Duration
	Invitation      time.Duration
	SignIn          time.Duration
	PasswordReset   time.Duration
	EmailChange     time.Duration
	PhoneChange     time.Duration
	TOTPReplacement time.Duration
}

// ErrLifetimeInvalid reports an ExpiresAt call with an unknown kind or a lifetime that is not
// positive: a fault in the caller or its configuration, never in a request.
var ErrLifetimeInvalid = errors.New("flow: invalid lifetime")

// ExpiresAt returns when a flow of kind k opened at now expires.
func ExpiresAt(k Kind, now time.Time, l Lifetimes) (time.Time, error) {
	var d time.Duration
	switch k {
	case KindRegistration:
		d = l.Registration
	case KindInvitation:
		d = l.Invitation
	case KindSignIn:
		d = l.SignIn
	case KindPasswordReset:
		d = l.PasswordReset
	case KindEmailChange:
		d = l.EmailChange
	case KindPhoneChange:
		d = l.PhoneChange
	case KindTOTPReplacement:
		d = l.TOTPReplacement
	default:
		return time.Time{}, fmt.Errorf("%w: unknown kind %q", ErrLifetimeInvalid, k)
	}
	if d <= 0 {
		return time.Time{}, fmt.Errorf("%w: %s lifetime %v", ErrLifetimeInvalid, k, d)
	}
	return now.Add(d), nil
}
