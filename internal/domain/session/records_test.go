package session

import (
	"errors"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/domain"
)

func TestParseRevokeReason(t *testing.T) {
	t.Parallel()

	if n := len(Reasons()); n != 11 {
		t.Errorf("%d reasons, want the 11 of TDD-04 §2", n)
	}
	for _, r := range Reasons() {
		if got, err := ParseRevokeReason(string(r)); err != nil || got != r {
			t.Errorf("ParseRevokeReason(%q) = %q, %v", r, got, err)
		}
	}
	for _, in := range []string{"", "expired", "Signed_Out", " operator"} {
		got, err := ParseRevokeReason(in)
		var de *domain.Error
		if got != "" || !errors.As(err, &de) || de.Code != domain.CodeValidationFailed {
			t.Errorf("ParseRevokeReason(%q) = %q, %v; want VALIDATION_FAILED", in, got, err)
		}
	}
}

func TestTokenCurrent(t *testing.T) {
	t.Parallel()

	now := time.Now()
	if !(Token{}).Current() {
		t.Error("a token never rotated is not current")
	}
	if (Token{RotatedAt: &now}).Current() {
		t.Error("a rotated token is current")
	}
}

func TestRevokeReasonValid(t *testing.T) {
	t.Parallel()

	for _, r := range Reasons() {
		if !r.Valid() {
			t.Errorf("%q is not valid", r)
		}
	}
	for _, r := range []RevokeReason{"", "expired", "Operator"} {
		if r.Valid() {
			t.Errorf("%q is valid", r)
		}
	}
}
