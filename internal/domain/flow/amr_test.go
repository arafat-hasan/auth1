package flow

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestAMR has one case per row of the TDD-03 §7 table; the "Any + enrolment confirmation" row is
// one case per first factor.
func TestAMR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		first  FirstFactor
		second SecondFactor
		want   []string
	}{
		{FirstFactorPassword, SecondNone, []string{"pwd"}},
		{FirstFactorSMS, SecondNone, []string{"sms"}},
		{FirstFactorEmail, SecondNone, []string{"email"}},
		{FirstFactorPassword, SecondTOTP, []string{"pwd", "otp", "mfa"}},
		{FirstFactorPassword, SecondRecoveryCode, []string{"pwd", "rcode", "mfa"}},
		{FirstFactorSMS, SecondTOTP, []string{"sms", "otp", "mfa"}},
		{FirstFactorEmail, SecondTOTP, []string{"email", "otp", "mfa"}},
		{FirstFactorSMS, SecondRecoveryCode, []string{"sms", "rcode", "mfa"}},
		{FirstFactorEmail, SecondRecoveryCode, []string{"email", "rcode", "mfa"}},
		{FirstFactorPassword, SecondEnrolment, []string{"pwd", "otp", "mfa"}},
		{FirstFactorSMS, SecondEnrolment, []string{"sms", "otp", "mfa"}},
		{FirstFactorEmail, SecondEnrolment, []string{"email", "otp", "mfa"}},
	}
	if len(tests) != 12 {
		t.Fatalf("%d cases, want 12", len(tests))
	}
	for _, tt := range tests {
		got, err := AMR(tt.first, tt.second)
		if err != nil {
			t.Errorf("AMR(%q, %q): %v", tt.first, tt.second, err)
			continue
		}
		if diff := cmp.Diff(tt.want, got); diff != "" {
			t.Errorf("AMR(%q, %q) (-want +got):\n%s", tt.first, tt.second, diff)
		}
	}
}

func TestAMRRefuses(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		first  FirstFactor
		second SecondFactor
	}{
		{"", SecondNone},
		{"otp", SecondNone},
		{"PWD", SecondTOTP},
		{FirstFactorPassword, "otp"},
		{FirstFactorPassword, "rcode"},
		{FirstFactorSMS, "sms"},
		{FirstFactorEmail, "TOTP"},
	} {
		if got, err := AMR(tt.first, tt.second); !errors.Is(err, ErrAMRUnlisted) || got != nil {
			t.Errorf("AMR(%q, %q) = %v, %v; want nil, ErrAMRUnlisted", tt.first, tt.second, got, err)
		}
	}
}

func TestAMRReturnsACopy(t *testing.T) {
	t.Parallel()

	a, _ := AMR(FirstFactorPassword, SecondTOTP)
	a[0] = "changed"
	if b, _ := AMR(FirstFactorPassword, SecondTOTP); b[0] != "pwd" {
		t.Errorf("AMR after a caller changed its result = %v", b)
	}
}
