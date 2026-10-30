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
// its type MOBILE or FIXED_LINE_OR_MOBILE. After the "+" only digits, white space and the
// separators of phoneRune may appear, brackets paired and the last a digit, and every digit must reach the E.164 form, so that two inputs
// do not silently meet: letters (read as vanity digits), extensions, trailing text and a national
// prefix after the calling code (+44 07…), all of which libphonenumber accepts, are refused.
func (Phone) Normalise(raw string, p Policy) (string, error) {
	s := strings.TrimSpace(raw)
	if len(s) > maxPhoneInput || !utf8.ValidString(s) {
		return "", notAllowed("the phone number is malformed")
	}
	rest, ok := strings.CutPrefix(s, "+")
	if !ok {
		rest, ok = strings.CutPrefix(s, "＋")
	}
	if !ok || strings.IndexFunc(rest, func(r rune) bool { return !phoneRune(r) }) >= 0 || !phoneShape(rest) {
		return "", notAllowed("the phone number is malformed")
	}
	n, err := phonenumbers.Parse(s, "")
	if err != nil || n.GetExtension() != "" || !phonenumbers.IsValidNumber(n) {
		return "", notAllowed("the phone number is not valid")
	}
	e164 := phonenumbers.Format(n, phonenumbers.E164)
	if digits(rest) != len(e164)-1 {
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
	return e164, nil
}

// phoneRune reports whether r may follow the "+" of a phone number: a decimal digit of any script,
// white space, or a separator - . ( ) / in ASCII or full width.
func phoneRune(r rune) bool {
	return unicode.IsDigit(r) || unicode.IsSpace(r) || strings.ContainsRune("-.()/－．（）／", r)
}

// phoneShape reports whether s ends in a digit and its brackets pair up, one level deep.
func phoneShape(s string) bool {
	last, _ := utf8.DecodeLastRuneInString(s)
	if !unicode.IsDigit(last) {
		return false
	}
	open := false
	for _, r := range s {
		switch r {
		case '(', '（':
			if open {
				return false
			}
			open = true
		case ')', '）':
			if !open {
				return false
			}
			open = false
		}
	}
	return !open
}

// digits returns the number of decimal digits in s.
func digits(s string) int {
	n := 0
	for _, r := range s {
		if unicode.IsDigit(r) {
			n++
		}
	}
	return n
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
