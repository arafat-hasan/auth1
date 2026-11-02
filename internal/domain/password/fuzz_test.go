package password

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// FuzzCheck: Check is deterministic, does not panic or modify the password, and returns each
// reason at most once, in the order of Reasons.
func FuzzCheck(f *testing.F) {
	for _, s := range []string{
		"correct horse battery", "ALICE alice", "straße STRASSE", "İpek ıpek i̇", "１２３４５６７８",
		"ﬁﬁﬁﬁﬁﬁ", "éé", "🔑 🌳", "\xff\xfe invalid", "", "ǅ ͅ ꭰ ẞ",
	} {
		f.Add([]byte(s), "alice")
	}
	d, err := ParseDenyList(strings.NewReader("alice1\npassword\n"))
	if err != nil {
		f.Fatal(err)
	}
	p := Policy{MinLength: 12, MaxLength: 64, DenyList: d}
	f.Fuzz(func(t *testing.T, pw []byte, variant string) {
		orig := bytes.Clone(pw)
		got := Check(pw, []string{variant}, p)
		if !bytes.Equal(pw, orig) {
			t.Fatalf("password changed: %q -> %q", orig, pw)
		}
		if again := Check(pw, []string{variant}, p); !slices.Equal(got, again) {
			t.Fatalf("not deterministic: %v then %v", got, again)
		}
		last := -1
		for _, r := range got {
			i := slices.Index(Reasons(), r)
			if i <= last {
				t.Fatalf("reasons %v: unknown, repeated or out of order", got)
			}
			last = i
		}
	})
}

// FuzzParseDenyList: parsing is deterministic and does not panic.
func FuzzParseDenyList(f *testing.F) {
	for _, s := range []string{"a\nb\r\nc", "\n\n", "x\xff\n", "  \n ẞ \n", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d1, err1 := ParseDenyList(strings.NewReader(s))
		d2, err2 := ParseDenyList(strings.NewReader(s))
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("not deterministic: %v then %v", err1, err2)
		}
		if err1 == nil && d1.Len() != d2.Len() {
			t.Fatalf("not deterministic: %d then %d entries", d1.Len(), d2.Len())
		}
	})
}

// BenchmarkParseDenyList parses a list of 100 000 passwords, the size TDD-03 §2 suggests.
func BenchmarkParseDenyList(b *testing.B) {
	var sb strings.Builder
	for i := range 100_000 {
		sb.WriteString("password")
		sb.WriteString(strings.Repeat("x", i%7))
		sb.WriteByte(byte('a' + i%26))
		sb.WriteString(string(rune('0' + i%10)))
		sb.WriteByte('\n')
	}
	s := sb.String()
	b.ResetTimer()
	for b.Loop() {
		if _, err := ParseDenyList(strings.NewReader(s)); err != nil {
			b.Fatal(err)
		}
	}
}
