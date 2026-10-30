package identifier

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

var phonePolicy = Policy{Verify: flow.MethodSMSOTP, CallingCodes: []string{"1", "39", "44", "49"}}

func TestPhoneNormalise(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		raw    string
		policy Policy
		want   string // empty: refused with IDENTIFIER_NOT_ALLOWED
	}{
		{"E.164 mobile", "+447400123456", phonePolicy, "+447400123456"},
		{"spaced", "+44 7400 123456", phonePolicy, "+447400123456"},
		{"punctuated", "+44 (7400) 123-456", phonePolicy, "+447400123456"},
		{"surrounding white space", "\t+44 7400 123456 ", phonePolicy, "+447400123456"},
		{"full-width digits", "+４４ ７４００ １２３４５６", phonePolicy, "+447400123456"},
		{"full-width plus", "＋447400123456", phonePolicy, "+447400123456"},
		{"fixed line or mobile under sms_otp", "+1 201-555-0123", phonePolicy, "+12015550123"},
		{"German mobile", "+49 151 23456789", phonePolicy, "+4915123456789"},
		{"Italian leading zero kept", "+39 02 1234 5678", Policy{CallingCodes: []string{"39"}}, "+390212345678"},
		{"fixed line without sms_otp", "+44 121 234 5678", Policy{CallingCodes: []string{"44"}}, "+441212345678"},
		// T-2.
		{"calling code not in the list", "+880 1812 345678", phonePolicy, ""},
		{"empty list allows no phone", "+447400123456", Policy{Verify: flow.MethodSMSOTP}, ""},
		{"fixed line under sms_otp", "+44 121 234 5678", phonePolicy, ""},
		{"toll free under sms_otp", "+44 800 123 4567", phonePolicy, ""},
		{"no plus", "447400123456", phonePolicy, ""},
		{"international prefix instead of plus", "0044 7400 123456", phonePolicy, ""},
		{"too short", "+44 7400 12345", phonePolicy, ""},
		{"unassigned calling code", "+999 123456789", Policy{CallingCodes: []string{"999"}}, ""},
		{"extension", "+44 7400 123456 ext. 12", phonePolicy, ""},
		{"vanity letters", "+1 800 FLOWERS", Policy{CallingCodes: []string{"1"}}, ""},
		{"empty", "", phonePolicy, ""},
		{"plus only", "+", phonePolicy, ""},
		{"too long", "+44 7400 123456" + string(make([]byte, 64)), phonePolicy, ""},
		{"invalid UTF-8", "+44 7400 \xff123456", phonePolicy, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Phone{}.Normalise(tt.raw, tt.policy)
			if tt.want == "" {
				checkNotAllowed(t, err)
				return
			}
			if err != nil {
				t.Fatalf("Normalise(%q) = %v", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("Normalise(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestPhoneVariants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		normalised string
		want       []string
	}{
		{"+447400123456", []string{"+447400123456", "447400123456", "7400123456"}},
		{"+390212345678", []string{"+390212345678", "390212345678", "0212345678"}},
	}
	for _, tt := range tests {
		if diff := cmp.Diff(tt.want, Phone{}.Variants(tt.normalised)); diff != "" {
			t.Errorf("Variants(%q) (-want +got):\n%s", tt.normalised, diff)
		}
	}
}

func TestPhoneDescribe(t *testing.T) {
	t.Parallel()
	p := Phone{}
	if p.Name() != "phone" || !p.CanSignIn() {
		t.Errorf("Name = %q, CanSignIn = %v", p.Name(), p.CanSignIn())
	}
	if diff := cmp.Diff([]flow.Method{flow.MethodSMSOTP}, p.VerifyMethods()); diff != "" {
		t.Errorf("VerifyMethods (-want +got):\n%s", diff)
	}
}

func FuzzPhone(f *testing.F) {
	for _, s := range []string{
		"+447400123456", "+44 7400 123456", "+４４７４００１２３４５６", "＋447400123456", "+12015550123",
		"+390212345678", "+44 121 234 5678", "+880 1812 345678", "+1 800 FLOWERS", "+44 7400 123456 ext. 12",
		"+", "", "+٤٤٧٤٠٠١٢٣٤٥٦", "+44 7400 ١٢٣٤٥٦",
	} {
		f.Add(s)
	}
	all := Policy{Verify: flow.MethodSMSOTP, CallingCodes: []string{"1", "33", "39", "44", "49", "880", "7"}}
	f.Fuzz(func(t *testing.T, raw string) {
		n, err := Phone{}.Normalise(raw, all)
		n2, err2 := Phone{}.Normalise(raw, all)
		if n != n2 || (err == nil) != (err2 == nil) {
			t.Fatalf("not deterministic: %q, %v then %q, %v", n, err, n2, err2)
		}
		if err != nil {
			checkNotAllowed(t, err)
			return
		}
		again, err := Phone{}.Normalise(n, all)
		if err != nil {
			t.Fatalf("Normalise(%q) = %q, which is refused: %v", raw, n, err)
		}
		if again != n {
			t.Fatalf("not idempotent: %q -> %q -> %q", raw, n, again)
		}
	})
}
