package identifier

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

var emailPolicy = Policy{Required: true, Verify: flow.MethodEmailLink, SignIn: true}

func TestEmailNormalise(t *testing.T) {
	t.Parallel()
	local64 := strings.Repeat("a", 64)
	label63 := strings.Repeat("b", 63)
	// 63+1+63+1+63+1+61 = 253 octets.
	domain253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("c", 57) + ".com"
	tests := []struct {
		name string
		raw  string
		want string // empty: refused with IDENTIFIER_NOT_ALLOWED
	}{
		{"plain", "alice@example.com", "alice@example.com"},
		{"mixed case", "Alice.Smith@Example.COM", "alice.smith@example.com"},
		{"surrounding white space", " \t alice@example.com\n", "alice@example.com"},
		{"plus tag kept", "alice+news@example.com", "alice+news@example.com"},
		{"dots kept", "a.l.i.c.e@example.com", "a.l.i.c.e@example.com"},
		{"split at the last @ refuses a bare @ in the local part", "a@b@example.com", ""},
		{"IDN domain", "info@Bücher.example", "info@xn--bcher-kva.example"},
		{"IDN domain in Punycode", "info@xn--bcher-kva.example", "info@xn--bcher-kva.example"},
		{"IDN domain upper case", "info@BÜCHER.example", "info@xn--bcher-kva.example"},
		{"sharp s domain is not transitional", "a@straße.example", "a@xn--strae-oqa.example"},
		{"full-width domain is mapped", "a@ｅｘａｍｐｌｅ.com", "a@example.com"},
		{"NFC local part", "josé@example.com", "josé@example.com"},
		{"Unicode local part folded", "ÉLODIE@example.com", "élodie@example.com"},
		{"sharp s local part kept", "straße@example.com", "straße@example.com"},
		{"capital sharp s folded", "STRAẞE@example.com", "straße@example.com"},
		{"Kelvin sign folds to k", "Kate@example.com", "kate@example.com"},
		{"Turkish dotted capital I kept", "İpek@example.com", "İpek@example.com"},
		{"Turkish dotless i kept", "ıpek@example.com", "ıpek@example.com"},
		{"final sigma folds", "ΟΔΟΣ@example.com", "οδοσ@example.com"},
		{"full-width digits in local part kept", "１２３@example.com", "１２３@example.com"},
		{"local part of 64 octets", local64 + "@example.com", local64 + "@example.com"},
		{"address of 255 octets", "a@" + domain253, ""},
		{"inner space", "alice smith@example.com", ""},
		{"inner tab", "alice@exa\tmple.com", ""},
		{"inner no-break space", "alice @example.com", ""},
		{"control character", "alice\x00@example.com", ""},
		{"zero-width space", "alice\u200b@example.com", ""},
		{"right-to-left override", "ali\u202ece@example.com", ""},
		{"soft hyphen", "al\u00adice@example.com", ""},
		{"byte order mark", "\ufeffalice@example.com", ""},
		{"private use", "alice\ue000@example.com", ""},
		{"local part starts with a combining mark", "\u0301@example.com", ""},
		{"local part starts with a spacing mark", "\u0903a@example.com", ""},
		{"empty", "", ""},
		{"white space only", "  ", ""},
		{"no @", "alice.example.com", ""},
		{"empty local part", "@example.com", ""},
		{"empty domain", "alice@", ""},
		{"local part of 65 octets", strings.Repeat("a", 65) + "@example.com", ""},
		{"local part over 64 octets after NFC", strings.Repeat("é", 33) + "@example.com", ""},
		{"domain without a dot", "alice@localhost", ""},
		{"display name", "Alice <alice@example.com>", ""},
		{"angle brackets", "<alice@example.com>", ""},
		{"quoted local part", `"alice"@example.com`, ""},
		{"comment", "alice@example.com(x)", ""},
		{"domain literal", "alice@[192.0.2.1]", ""},
		{"trailing dot", "alice@example.com.", ""},
		{"leading dot in local part", ".alice@example.com", ""},
		{"label over 63 octets", "a@" + strings.Repeat("d", 64) + ".com", ""},
		{"underscore in domain", "a@ex_ample.com", ""},
		{"invalid Punycode", "a@xn--a.example", ""},
		{"invalid UTF-8", "a\xff@example.com", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Email{}.Normalise(tt.raw, emailPolicy)
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

func TestEmailLengths(t *testing.T) {
	t.Parallel()
	// 64 + 1 + 189 = 254 octets: the longest address.
	domain := strings.Repeat("d", 63) + "." + strings.Repeat("e", 63) + "." + strings.Repeat("f", 57) + ".com"
	ok := strings.Repeat("a", 64) + "@" + domain
	if len(ok) != 254 {
		t.Fatalf("test address is %d octets", len(ok))
	}
	if _, err := (Email{}).Normalise(ok, emailPolicy); err != nil {
		t.Errorf("254 octets: %v", err)
	}
	long := strings.Repeat("a", 64) + "@g" + domain
	checkNotAllowed(t, func() error { _, err := (Email{}).Normalise(long, emailPolicy); return err }())
}

func TestEmailVariants(t *testing.T) {
	t.Parallel()
	got := Email{}.Variants("alice.smith@example.com")
	if diff := cmp.Diff([]string{"alice.smith@example.com", "alice.smith"}, got); diff != "" {
		t.Errorf("Variants (-want +got):\n%s", diff)
	}
}

func TestEmailDescribe(t *testing.T) {
	t.Parallel()
	e := Email{}
	if e.Name() != "email" || !e.CanSignIn() {
		t.Errorf("Name = %q, CanSignIn = %v", e.Name(), e.CanSignIn())
	}
	if diff := cmp.Diff([]flow.Method{flow.MethodEmailLink, flow.MethodEmailCode}, e.VerifyMethods()); diff != "" {
		t.Errorf("VerifyMethods (-want +got):\n%s", diff)
	}
}

// TestEmailNoCollisions checks R-4: inputs that look alike but differ under the rules stay apart.
func TestEmailNoCollisions(t *testing.T) {
	t.Parallel()
	groups := [][]string{
		{"strasse@example.com", "straße@example.com"},
		{"ipek@example.com", "İpek@example.com", "ıpek@example.com", "i̇pek@example.com"},
		{"123@example.com", "１２３@example.com"},
		{"a@strasse.example", "a@straße.example"},
		{"paypal@example.com", "pаypal@example.com"}, // Cyrillic а
	}
	for _, g := range groups {
		seen := map[string]string{}
		for _, raw := range g {
			n, err := Email{}.Normalise(raw, emailPolicy)
			if err != nil {
				t.Fatalf("Normalise(%q) = %v; the group compares accepted values", raw, err)
			}
			if other, ok := seen[n]; ok {
				t.Errorf("%q and %q both normalise to %q", other, raw, n)
			}
			seen[n] = raw
		}
	}
}

func FuzzEmail(f *testing.F) {
	for _, s := range []string{
		"alice@example.com", "Alice@Example.COM", "info@Bücher.example", "a@xn--bcher-kva.example",
		"straße@straße.example", "STRAẞE@example.com", "İpek@example.com", "ıpek@example.com",
		"i̇@example.com", "１２３@ｅｘａｍｐｌｅ.com", "K@example.com", "ΟΔΟΣ@example.com",
		"josé@example.com", "a b@example.com", `"a"@example.com`, "a@b@example.com", "",
		"ẞ@example.com", "ͅ@example.com", "ǅ@example.com", "ꭰ@example.com",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		n, err := Email{}.Normalise(raw, emailPolicy)
		n2, err2 := Email{}.Normalise(raw, emailPolicy)
		if n != n2 || (err == nil) != (err2 == nil) {
			t.Fatalf("not deterministic: %q, %v then %q, %v", n, err, n2, err2)
		}
		if err != nil {
			checkNotAllowed(t, err)
			return
		}
		if !utf8.ValidString(n) || len(n) > 254 {
			t.Fatalf("Normalise(%q) = %q: invalid or too long", raw, n)
		}
		again, err := Email{}.Normalise(n, emailPolicy)
		if err != nil {
			t.Fatalf("Normalise(%q) = %q, which is refused: %v", raw, n, err)
		}
		if again != n {
			t.Fatalf("not idempotent: %q -> %q -> %q", raw, n, again)
		}
	})
}

// checkNotAllowed fails the test unless err is a *domain.Error with code IDENTIFIER_NOT_ALLOWED.
func checkNotAllowed(t *testing.T, err error) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeIdentifierNotAllowed {
		t.Fatalf("error = %v, want IDENTIFIER_NOT_ALLOWED", err)
	}
}

// TestSimpleFoldUnicodeVersion fails when Go's Unicode tables change version: simpleFold's
// exceptions were checked against CaseFolding.txt of this version, and a new version may add status
// S pairs or Cherokee-like orbits that change stored values. Re-check them, then update the version.
func TestSimpleFoldUnicodeVersion(t *testing.T) {
	t.Parallel()
	if unicode.Version != "17.0.0" {
		t.Errorf("unicode.Version = %s: re-check simpleFold against its CaseFolding.txt", unicode.Version)
	}
}

// TestSimpleFold checks every rune: folding is idempotent, and the runes of one simple-fold orbit
// (unicode.SimpleFold) fold to the same rune, so case-insensitive equality is equality after it.
func TestSimpleFold(t *testing.T) {
	t.Parallel()
	for r := rune(0); r <= unicode.MaxRune; r++ {
		f := simpleFold(r)
		if simpleFold(f) != f {
			t.Errorf("simpleFold(%U) = %U, which folds to %U", r, f, simpleFold(f))
		}
		if o := unicode.SimpleFold(r); simpleFold(o) != f {
			t.Errorf("simpleFold(%U) = %U, but simpleFold(%U) = %U", r, f, o, simpleFold(o))
		}
	}
}
