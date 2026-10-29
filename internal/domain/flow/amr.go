package flow

import (
	"errors"
	"fmt"
	"slices"
)

// SecondFactor is the second factor a sign-in passed, if any (TDD-03 §3, §4.1).
type SecondFactor string

// The second factors.
const (
	SecondNone         SecondFactor = ""              // none: no TOTP, on an optional client
	SecondTOTP         SecondFactor = "totp"          // a TOTP code
	SecondRecoveryCode SecondFactor = "recovery_code" // a recovery code
	SecondEnrolment    SecondFactor = "enrolment"     // the code confirming a forced enrolment
)

type factors struct {
	first  FirstFactor
	second SecondFactor
}

// amrs is the TDD-03 §7 table, row by row; the "Any + enrolment confirmation" row is "as with
// TOTP" for each first factor.
var amrs = map[factors][]string{
	{FirstFactorPassword, SecondNone}:         {"pwd"},
	{FirstFactorSMS, SecondNone}:              {"sms"},
	{FirstFactorEmail, SecondNone}:            {"email"},
	{FirstFactorPassword, SecondTOTP}:         {"pwd", "otp", "mfa"},
	{FirstFactorPassword, SecondRecoveryCode}: {"pwd", "rcode", "mfa"},
	{FirstFactorSMS, SecondTOTP}:              {"sms", "otp", "mfa"},
	{FirstFactorEmail, SecondTOTP}:            {"email", "otp", "mfa"},
	{FirstFactorSMS, SecondRecoveryCode}:      {"sms", "rcode", "mfa"},
	{FirstFactorEmail, SecondRecoveryCode}:    {"email", "rcode", "mfa"},
	{FirstFactorPassword, SecondEnrolment}:    {"pwd", "otp", "mfa"},
	{FirstFactorSMS, SecondEnrolment}:         {"sms", "otp", "mfa"},
	{FirstFactorEmail, SecondEnrolment}:       {"email", "otp", "mfa"},
}

// ErrAMRUnlisted reports a pair of factors that the TDD-03 §7 table does not list: a fault in the
// caller, never in a request.
var ErrAMRUnlisted = errors.New("flow: no amr for these factors")

// AMR returns the session's amr for a sign-in that passed first and then second (TDD-03 §7), as a
// new slice in the table's order. A pair the table does not list is ErrAMRUnlisted.
func AMR(first FirstFactor, second SecondFactor) ([]string, error) {
	amr, ok := amrs[factors{first, second}]
	if !ok {
		return nil, fmt.Errorf("%w: first %q, second %q", ErrAMRUnlisted, first, second)
	}
	return slices.Clone(amr), nil
}
