package password

import (
	"bytes"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// Reason is why a password fails the policy: a value of PASSWORD_REJECTED.reasons (SDD §10).
type Reason string

// The reasons, in the order Check tests them (TDD-03 §2).
const (
	TooShort           Reason = "too_short"
	TooLong            Reason = "too_long"
	ContainsIdentifier Reason = "contains_identifier"
	Common             Reason = "common"
)

// Reasons returns every reason, in the order Check tests them.
func Reasons() []Reason { return []Reason{TooShort, TooLong, ContainsIdentifier, Common} }

// minVariant is the length, in code points of the comparison form, under which an identifier
// variant is ignored.
const minVariant = 4

// Policy is the configured password policy: passwords.min_length and passwords.max_length, in code
// points of the NFKC form, and the deny-list, which refuses nothing when nil.
type Policy struct {
	MinLength int
	MaxLength int
	DenyList  *DenyList
}

// Check returns every reason password fails p, in the order of Reasons, or nil when it passes.
// variants are the Variants of the account's identifiers (TDD-01 §2). password is not modified.
func Check(password []byte, variants []string, p Policy) []Reason {
	var out []Reason
	n := utf8.RuneCount(norm.NFKC.Bytes(password))
	if n < p.MinLength {
		out = append(out, TooShort)
	}
	if n > p.MaxLength {
		out = append(out, TooLong)
	}
	folded := fold(password)
	for _, v := range variants {
		fv := fold([]byte(v))
		if utf8.RuneCount(fv) >= minVariant && bytes.Contains(folded, fv) {
			out = append(out, ContainsIdentifier)
			break
		}
	}
	if p.DenyList != nil && p.DenyList.contains(folded) {
		out = append(out, Common)
	}
	return out
}

// Rejected returns the PASSWORD_REJECTED error carrying reasons, or nil when there are none.
func Rejected(reasons []Reason) error {
	if len(reasons) == 0 {
		return nil
	}
	s := make([]string, len(reasons))
	for i, r := range reasons {
		s[i] = string(r)
	}
	return &domain.Error{Code: domain.CodePasswordRejected, Detail: "the password does not meet the policy", Reasons: s}
}

// fold returns the comparison form of s, NFKC(fold(NFKC(s))) with full case folding (TDD-03 §2),
// in a new slice. A Caser holds state, so each call makes its own.
func fold(s []byte) []byte {
	return norm.NFKC.Bytes(cases.Fold().Bytes(norm.NFKC.Bytes(s)))
}
