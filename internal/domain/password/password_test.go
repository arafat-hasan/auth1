package password

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/identifier"
)

var defaultPolicy = Policy{MinLength: 12, MaxLength: 64}

func TestLength(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		password string
		policy   Policy
		want     []Reason
	}{
		{"one under the minimum", strings.Repeat("a", 11), defaultPolicy, []Reason{TooShort}},
		{"the minimum", strings.Repeat("a", 12), defaultPolicy, nil},
		{"the maximum", strings.Repeat("a", 64), defaultPolicy, nil},
		{"one over the maximum", strings.Repeat("a", 65), defaultPolicy, []Reason{TooLong}},
		{"code points, not bytes", strings.Repeat("é", 64), defaultPolicy, nil},
		{"counted after NFKC: ligatures expand", strings.Repeat("ﬁ", 6), defaultPolicy, nil},
		{"counted after NFKC: combining marks compose", strings.Repeat("é", 12), Policy{MinLength: 8, MaxLength: 12}, nil},
		{"counted before case folding", "ßßßßßßx", Policy{MinLength: 8, MaxLength: 64}, []Reason{TooShort}},
		{"spaces and emoji accepted", "a b c 🔑 d e f 🌳", defaultPolicy, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, Check([]byte(tc.password), nil, tc.policy)); diff != "" {
				t.Errorf("Check(%q) (-want +got):\n%s", tc.password, diff)
			}
		})
	}
}

// TestT3PhoneNationalForm: T-3, a password containing the account's phone in national form is
// refused.
func TestT3PhoneNationalForm(t *testing.T) {
	t.Parallel()
	variants := identifier.Phone{}.Variants("+447911123456")
	for _, pw := range []string{
		"my 07911123456 dog!",   // the national form, with its trunk prefix
		"my 7911123456 dog!!",   // the national significant number
		"my +447911123456 dog!", // E.164
		"my 447911123456 dog!",  // E.164 without +
	} {
		if diff := cmp.Diff([]Reason{ContainsIdentifier}, Check([]byte(pw), variants, defaultPolicy)); diff != "" {
			t.Errorf("Check(%q) (-want +got):\n%s", pw, diff)
		}
	}
}

// TestShortVariantIgnored: a variant shorter than 4 code points, such as a short email local part,
// does not refuse unrelated passwords; one of 4 does.
func TestShortVariantIgnored(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		variants []string
		password string
		want     []Reason
	}{
		{"short local part", identifier.Email{}.Variants("ab@ex.io"), "fabulous tablecloth", nil},
		{"the address is still checked", identifier.Email{}.Variants("ab@ex.io"), "xx ab@ex.io xx", []Reason{ContainsIdentifier}},
		{"3 code points ignored", []string{"abc"}, "abcabcabcabc", nil},
		{"4 code points checked", []string{"abcd"}, "xx abcd xx yy", []Reason{ContainsIdentifier}},
		{"short once normalised", []string{"éé"}, "café éé é é é", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, Check([]byte(tc.password), tc.variants, defaultPolicy)); diff != "" {
				t.Errorf("Check(%q) (-want +got):\n%s", tc.password, diff)
			}
		})
	}
}

// TestCaseFolded: the password and the variants are compared as NFKC(fold(NFKC(s))).
func TestCaseFolded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		variant  string
		password string
	}{
		{"upper case", "alice", "my ALICE password"},
		{"upper-case variant", "ALICE", "my alice password"},
		{"full folding", "straße", "STRASSE-forever-1"},
		{"full-width", "alice", "my ａｌｉｃｅ password"},
		{"decomposed", "josé", "my josé password"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff([]Reason{ContainsIdentifier}, Check([]byte(tc.password), []string{tc.variant}, defaultPolicy)); diff != "" {
				t.Errorf("Check(%q) (-want +got):\n%s", tc.password, diff)
			}
		})
	}
}

// TestPasswordUnchanged: Check does not modify the caller's password.
func TestPasswordUnchanged(t *testing.T) {
	t.Parallel()
	pw := []byte("my ALICE ﬁ password")
	orig := bytes.Clone(pw)
	Check(pw, []string{"alice"}, defaultPolicy)
	if !bytes.Equal(pw, orig) {
		t.Errorf("password changed: %q, want %q", pw, orig)
	}
}

func TestRejected(t *testing.T) {
	t.Parallel()
	if err := Rejected(nil); err != nil {
		t.Errorf("Rejected(nil) = %v, want nil", err)
	}
	err := Rejected([]Reason{TooShort, Common})
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("Rejected = %v, want a *domain.Error", err)
	}
	if de.Code != domain.CodePasswordRejected {
		t.Errorf("Code = %s, want %s", de.Code, domain.CodePasswordRejected)
	}
	if diff := cmp.Diff([]string{"too_short", "common"}, de.Reasons); diff != "" {
		t.Errorf("Reasons (-want +got):\n%s", diff)
	}
}

func TestReasons(t *testing.T) {
	t.Parallel()
	want := []Reason{"too_short", "too_long", "contains_identifier", "common"}
	if diff := cmp.Diff(want, Reasons()); diff != "" {
		t.Errorf("Reasons (-want +got):\n%s", diff)
	}
}
