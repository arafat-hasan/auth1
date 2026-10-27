package domain

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCodes(t *testing.T) {
	t.Parallel()

	// SDD §10, in its order.
	want := []Code{
		"VALIDATION_FAILED", "IDENTIFIER_NOT_ALLOWED", "PASSWORD_REJECTED", "IDENTIFIER_TAKEN",
		"VERIFICATION_INCOMPLETE", "CODE_INVALID", "CHALLENGE_CLOSED", "RESEND_TOO_SOON",
		"INVALID_CREDENTIALS", "SIGN_IN_DELAYED", "REGISTRATION_INCOMPLETE", "ROLE_NOT_PERMITTED",
		"ACCOUNT_RESTRICTED", "SESSION_INVALID", "TOKEN_INVALID", "REAUTHENTICATION_REQUIRED",
		"CALLER_NOT_ALLOWED", "IDEMPOTENCY_KEY_REUSED", "STATUS_TRANSITION_INVALID",
		"MFA_STATE_INVALID", "ROLE_UNKNOWN", "NOT_FOUND", "RATE_LIMITED", "UNAVAILABLE",
	}
	if diff := cmp.Diff(want, Codes()); diff != "" {
		t.Errorf("Codes() (-want +got):\n%s", diff)
	}

	constants := []Code{
		CodeValidationFailed, CodeIdentifierNotAllowed, CodePasswordRejected, CodeIdentifierTaken,
		CodeVerificationIncomplete, CodeCodeInvalid, CodeChallengeClosed, CodeResendTooSoon,
		CodeInvalidCredentials, CodeSignInDelayed, CodeRegistrationIncomplete, CodeRoleNotPermitted,
		CodeAccountRestricted, CodeSessionInvalid, CodeTokenInvalid, CodeReauthenticationRequired,
		CodeCallerNotAllowed, CodeIdempotencyKeyReused, CodeStatusTransitionInvalid,
		CodeMFAStateInvalid, CodeRoleUnknown, CodeNotFound, CodeRateLimited, CodeUnavailable,
	}
	if diff := cmp.Diff(want, constants); diff != "" {
		t.Errorf("constants (-want +got):\n%s", diff)
	}
}

func TestCodesReturnsACopy(t *testing.T) {
	t.Parallel()

	Codes()[0] = "CHANGED"
	if Codes()[0] != CodeValidationFailed {
		t.Error("changing the result of Codes changed the catalogue")
	}
}

func TestErrorAs(t *testing.T) {
	t.Parallel()

	left := 2
	err := fmt.Errorf("wrap: %w", &Error{Code: CodeCodeInvalid, Detail: "d", AttemptsLeft: &left})
	var de *Error
	if !errors.As(err, &de) {
		t.Fatal("errors.As did not find the *Error")
	}
	if de.Code != CodeCodeInvalid || *de.AttemptsLeft != 2 {
		t.Errorf("got %+v", de)
	}
}

func TestErrorString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err  *Error
		want string
	}{
		{&Error{Code: CodeNotFound, Detail: "no such account"}, "NOT_FOUND: no such account"},
		{&Error{Code: CodeNotFound}, "NOT_FOUND"},
	}
	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
	}
}
