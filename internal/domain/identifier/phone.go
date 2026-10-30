package identifier

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nyaruka/phonenumbers"

	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// maxPhoneInput bounds the work done on an input before libphonenumber parses it.
const maxPhoneInput = 64

// Phone is the phone type (TDD-01 §2.3).
type Phone struct{}

// Name returns "phone".
func (Phone) Name() string { return "phone" }

// CanSignIn returns true.
func (Phone) CanSignIn() bool { return true }

// VerifyMethods returns sms_otp.
func (Phone) VerifyMethods() []flow.Method { return []flow.Method{flow.MethodSMSOTP} }

// Normalise applies TDD-01 §2.3 and returns the number in E.164. The trimmed input must start with
// "+" (or a full-width "＋"): there is no default region. The number must be valid for its region,
// its calling code in p.CallingCodes (an empty list allows none), and, when p.Verify is sms_otp,
// its type MOBILE or FIXED_LINE_OR_MOBILE. Letters, which libphonenumber would read as vanity
// digits, and extensions, which E.164 would drop, are refused so that two inputs do not silently
// meet.
func (Phone) Normalise(raw string, p Policy) (string, error) {
	s := strings.TrimSpace(raw)
	if len(s) > maxPhoneInput || !utf8.ValidString(s) ||
		!strings.HasPrefix(s, "+") && !strings.HasPrefix(s, "＋") ||
		strings.IndexFunc(s, unicode.IsLetter) >= 0 {
		return "", notAllowed("the phone number is malformed")
	}
	n, err := phonenumbers.Parse(s, "")
	if err != nil || n.GetExtension() != "" || !phonenumbers.IsValidNumber(n) {
		return "", notAllowed("the phone number is not valid")
	}
	if !slices.Contains(p.CallingCodes, strconv.Itoa(int(n.GetCountryCode()))) {
		return "", notAllowed("the phone number's calling code is not allowed")
	}
	if p.Verify == flow.MethodSMSOTP {
		if t := phonenumbers.GetNumberType(n); t != phonenumbers.MOBILE && t != phonenumbers.FIXED_LINE_OR_MOBILE {
			return "", notAllowed("the phone number cannot receive SMS")
		}
	}
	return phonenumbers.Format(n, phonenumbers.E164), nil
}

// Variants returns the E.164 form, the form without "+" and the national significant number.
func (Phone) Variants(normalised string) []string {
	out := []string{normalised, strings.TrimPrefix(normalised, "+")}
	if n, err := phonenumbers.Parse(normalised, ""); err == nil {
		out = append(out, phonenumbers.GetNationalSignificantNumber(n))
	}
	return out
}

// CheckPolicy refuses a calling code that is not assigned, and an empty calling-code list on a
// phone that is required or can sign in, since that list allows no phone at all.
func (ph Phone) CheckPolicy(p Policy) []PolicyError {
	var out []PolicyError
	for i, code := range p.CallingCodes {
		c, err := strconv.Atoi(code)
		if err != nil || strconv.Itoa(c) != code || phonenumbers.GetRegionCodeForCountryCode(c) == "ZZ" {
			out = append(out, PolicyError{
				Type: ph.Name(), Field: fmt.Sprintf("calling_codes[%d]", i),
				Message: fmt.Sprintf("%q is not an assigned calling code", code),
			})
		}
	}
	if len(p.CallingCodes) == 0 && (p.Required || p.SignIn) {
		out = append(out, PolicyError{
			Type: ph.Name(), Field: "calling_codes",
			Message: "is empty, so no phone is allowed; required or sign_in needs at least one",
		})
	}
	return out
}
