package domain

import (
	"slices"
	"time"
)

// Code is a stable error code from the SDD §10 catalogue. The HTTP layer maps each code to its
// status; the domain knows nothing of HTTP.
type Code string

// The SDD §10 error codes.
const (
	CodeValidationFailed         Code = "VALIDATION_FAILED"
	CodeIdentifierNotAllowed     Code = "IDENTIFIER_NOT_ALLOWED"
	CodePasswordRejected         Code = "PASSWORD_REJECTED"
	CodeIdentifierTaken          Code = "IDENTIFIER_TAKEN"
	CodeVerificationIncomplete   Code = "VERIFICATION_INCOMPLETE"
	CodeCodeInvalid              Code = "CODE_INVALID"
	CodeChallengeClosed          Code = "CHALLENGE_CLOSED"
	CodeResendTooSoon            Code = "RESEND_TOO_SOON"
	CodeInvalidCredentials       Code = "INVALID_CREDENTIALS" //nolint:gosec // an error code, not a credential
	CodeSignInDelayed            Code = "SIGN_IN_DELAYED"
	CodeRegistrationIncomplete   Code = "REGISTRATION_INCOMPLETE"
	CodeRoleNotPermitted         Code = "ROLE_NOT_PERMITTED"
	CodeAccountRestricted        Code = "ACCOUNT_RESTRICTED"
	CodeSessionInvalid           Code = "SESSION_INVALID"
	CodeTokenInvalid             Code = "TOKEN_INVALID"
	CodeReauthenticationRequired Code = "REAUTHENTICATION_REQUIRED"
	CodeCallerNotAllowed         Code = "CALLER_NOT_ALLOWED"
	CodeIdempotencyKeyReused     Code = "IDEMPOTENCY_KEY_REUSED"
	CodeStatusTransitionInvalid  Code = "STATUS_TRANSITION_INVALID"
	CodeMFAStateInvalid          Code = "MFA_STATE_INVALID"
	CodeRoleUnknown              Code = "ROLE_UNKNOWN"
	CodeNotFound                 Code = "NOT_FOUND"
	CodeRateLimited              Code = "RATE_LIMITED"
	CodeUnavailable              Code = "UNAVAILABLE"
)

// codes is the catalogue in SDD §10 order.
var codes = []Code{
	CodeValidationFailed, CodeIdentifierNotAllowed, CodePasswordRejected, CodeIdentifierTaken,
	CodeVerificationIncomplete, CodeCodeInvalid, CodeChallengeClosed, CodeResendTooSoon,
	CodeInvalidCredentials, CodeSignInDelayed, CodeRegistrationIncomplete, CodeRoleNotPermitted,
	CodeAccountRestricted, CodeSessionInvalid, CodeTokenInvalid, CodeReauthenticationRequired,
	CodeCallerNotAllowed, CodeIdempotencyKeyReused, CodeStatusTransitionInvalid,
	CodeMFAStateInvalid, CodeRoleUnknown, CodeNotFound, CodeRateLimited, CodeUnavailable,
}

// Codes returns every code of the catalogue, in SDD §10 order.
func Codes() []Code { return slices.Clone(codes) }

// FieldError names one malformed field of a VALIDATION_FAILED error and why it failed.
type FieldError struct {
	Field string
	Code  string
}

// Error is a domain failure: a catalogue code, a message safe to show the caller, and the
// optional members some codes carry. Match it with errors.As and a *Error target.
type Error struct {
	Code         Code
	Detail       string        // safe to return to the caller; never holds secret or personal data
	RetryAfter   time.Duration // when the caller may retry; zero for none
	AttemptsLeft *int          // for CODE_INVALID
	Reasons      []string      // for PASSWORD_REJECTED
	Fields       []FieldError  // for VALIDATION_FAILED
}

// Error returns "<CODE>: <detail>", or the code alone when there is no detail.
func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Detail
}
