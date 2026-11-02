package password

import (
	"errors"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/google/go-cmp/cmp"
)

func TestParseDenyList(t *testing.T) {
	t.Parallel()
	d, err := ParseDenyList(strings.NewReader("Password1\r\nletmein\n\n  \nqwerty 123 \nletmein\nlast"))
	if err != nil {
		t.Fatalf("ParseDenyList: %v", err)
	}
	// Password1, letmein, "  ", "qwerty 123 ", last: blank lines skipped, duplicates once, other
	// white space kept.
	if got := d.Len(); got != 5 {
		t.Errorf("Len = %d, want 5", got)
	}
	for _, pw := range []string{"Password1", "PASSWORD1", "ｐａｓｓｗｏｒｄ1", "letmein", "qwerty 123 ", "last"} {
		if !d.contains(fold([]byte(pw))) {
			t.Errorf("%q not listed", pw)
		}
	}
	for _, pw := range []string{"Password1\r", "qwerty 123", "", "\n"} {
		if d.contains(fold([]byte(pw))) {
			t.Errorf("%q listed", pw)
		}
	}
}

func TestParseDenyListEmpty(t *testing.T) {
	t.Parallel()
	d, err := ParseDenyList(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseDenyList: %v", err)
	}
	if d.Len() != 0 {
		t.Errorf("Len = %d, want 0", d.Len())
	}
}

// TestParseDenyListInvalid: a bad file is refused, naming the line and never its contents.
func TestParseDenyListInvalid(t *testing.T) {
	t.Parallel()
	secret := "hunter2-secret"
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"invalid UTF-8", "fine\n" + secret + "\xff\n", "line 2: not UTF-8"},
		{"line too long", "fine\nfine\n" + secret + strings.Repeat("x", maxLine) + "\n", "line 3: longer than 65536 bytes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseDenyList(strings.NewReader(tc.input))
			if err == nil {
				t.Fatal("ParseDenyList: no error")
			}
			if err.Error() != tc.want {
				t.Errorf("error = %q, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q holds the line", err)
			}
		})
	}
}

func TestParseDenyListReadError(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	_, err := ParseDenyList(iotest.ErrReader(boom))
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap %v", err, boom)
	}
}

func TestCommon(t *testing.T) {
	t.Parallel()
	d, err := ParseDenyList(strings.NewReader("correcthorse\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{MinLength: 12, MaxLength: 64, DenyList: d}
	tests := []struct {
		password string
		want     []Reason
	}{
		{"correcthorse", []Reason{Common}},
		{"CorrectHorse", []Reason{Common}},
		{"ｃｏｒｒｅｃｔｈｏｒｓｅ", []Reason{Common}},
		{"correcthorse battery", nil}, // contains a listed password, but is not one
	}
	for _, tc := range tests {
		if diff := cmp.Diff(tc.want, Check([]byte(tc.password), nil, p)); diff != "" {
			t.Errorf("Check(%q) (-want +got):\n%s", tc.password, diff)
		}
	}
	if got := Check([]byte("correcthorse"), nil, Policy{MinLength: 12, MaxLength: 64}); got != nil {
		t.Errorf("no deny-list: Check = %v, want nil", got)
	}
}

// TestEveryReason: every reason that applies is returned, in the order of Reasons.
func TestEveryReason(t *testing.T) {
	t.Parallel()
	d, err := ParseDenyList(strings.NewReader("alice1\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{MinLength: 8, MaxLength: 64, DenyList: d}
	variants := []string{"alice@example.com", "alice"}
	if diff := cmp.Diff([]Reason{TooShort, ContainsIdentifier, Common}, Check([]byte("Alice1"), variants, p)); diff != "" {
		t.Errorf("short (-want +got):\n%s", diff)
	}
	long := []byte("alice" + strings.Repeat("x", 60))
	if diff := cmp.Diff([]Reason{TooLong, ContainsIdentifier}, Check(long, variants, p)); diff != "" {
		t.Errorf("long (-want +got):\n%s", diff)
	}
}
