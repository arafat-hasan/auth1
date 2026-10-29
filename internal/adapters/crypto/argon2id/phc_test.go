package argon2id

import (
	"errors"
	"strings"
	"testing"

	"github.com/arafat-hasan/auth1/internal/app"
)

// testPHC is a PHC value with recognisable salt and hash bytes.
func testPHC(params Params) phc {
	var v phc
	v.params = params
	for i := range v.salt {
		v.salt[i] = byte(i + 1)
	}
	for i := range v.hash {
		v.hash[i] = byte(0xa0 + i)
	}
	return v
}

func TestPHCRoundTrip(t *testing.T) {
	t.Parallel()
	for _, params := range []Params{
		{MemoryKiB: 65536, Iterations: 2, Parallelism: 1},
		{MemoryKiB: 8, Iterations: 1, Parallelism: 1},
		{MemoryKiB: 1 << 20, Iterations: 16, Parallelism: 16},
	} {
		v := testPHC(params)
		s := v.encode()
		got, err := parsePHC(s)
		if err != nil {
			t.Fatalf("parsePHC(%q): %v", s, err)
		}
		if got != v {
			t.Errorf("parsePHC(%q) = %+v, want %+v", s, got, v)
		}
	}
}

// TestPHCFormat: the default parameters encode as in TDD-03 §1.2.
func TestPHCFormat(t *testing.T) {
	t.Parallel()
	const want = "$argon2id$v=19$m=65536,t=2,p=1$AQIDBAUGBwgJCgsMDQ4PEA$oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8"
	if got := testPHC(Params{MemoryKiB: 65536, Iterations: 2, Parallelism: 1}).encode(); got != want {
		t.Errorf("encode = %q, want %q", got, want)
	}
}

func TestParsePHCRefuses(t *testing.T) {
	t.Parallel()
	valid := testPHC(Params{MemoryKiB: 65536, Iterations: 2, Parallelism: 1}).encode()
	const salt, hash = "AQIDBAUGBwgJCgsMDQ4PEA", "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8"
	with := func(params string) string { return "$argon2id$v=19$" + params + "$" + salt + "$" + hash }
	for _, tt := range []struct{ name, in string }{
		{"empty", ""},
		{"argon2i", strings.Replace(valid, "argon2id", "argon2i", 1)},
		{"version 16", strings.Replace(valid, "v=19", "v=16", 1)},
		{"no version", strings.Replace(valid, "$v=19", "", 1)},
		{"version leading zero", strings.Replace(valid, "v=19", "v=019", 1)},
		{"parameters out of order", with("t=2,m=65536,p=1")},
		{"missing parameter", with("m=65536,t=2")},
		{"extra parameter", with("m=65536,t=2,p=1,k=1")},
		{"leading zero", with("m=065536,t=2,p=1")},
		{"plus sign", with("m=+65536,t=2,p=1")},
		{"spaces", with("m=65536, t=2,p=1")},
		{"memory above 1 GiB", with("m=1048577,t=2,p=1")},
		{"memory huge", with("m=99999999999999999999,t=2,p=1")},
		{"memory below 8 per lane", with("m=15,t=1,p=2")},
		{"iterations 0", with("m=65536,t=0,p=1")},
		{"iterations 17", with("m=65536,t=17,p=1")},
		{"parallelism 0", with("m=65536,t=2,p=0")},
		{"parallelism 17", with("m=65536,t=2,p=17")},
		{"salt 15 bytes", strings.Replace(valid, salt, "AQIDBAUGBwgJCgsMDQ4P", 1)},
		{"salt 17 bytes", strings.Replace(valid, salt, "AQIDBAUGBwgJCgsMDQ4PEBE", 1)},
		{"hash 31 bytes", strings.Replace(valid, hash, hash[:41], 1)},
		{"hash 33 bytes", strings.Replace(valid, hash, hash+"wA", 1)},
		{"padded base64", strings.Replace(valid, salt, salt+"==", 1)},
		{"non-canonical trailing bits", strings.Replace(valid, salt, salt[:21]+"B", 1)},
		{"url base64", strings.Replace(valid, hash, strings.ReplaceAll(hash, "+", "-"), 1) + "-"},
		{"trailing dollar", valid + "$"},
		{"no leading dollar", valid[1:]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parsePHC(tt.in)
			if !errors.Is(err, app.ErrPasswordHashInvalid) {
				t.Fatalf("parsePHC(%q) = %v, want ErrPasswordHashInvalid", tt.in, err)
			}
			if strings.Contains(err.Error(), salt) || strings.Contains(err.Error(), hash[:20]) {
				t.Errorf("error %q quotes the input", err)
			}
		})
	}
}

func TestParamsValidate(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		p  Params
		ok bool
	}{
		{Params{MemoryKiB: 65536, Iterations: 2, Parallelism: 1}, true},
		{Params{MemoryKiB: 8, Iterations: 1, Parallelism: 1}, true},
		{Params{MemoryKiB: 1 << 20, Iterations: 16, Parallelism: 16}, true},
		{Params{MemoryKiB: 7, Iterations: 1, Parallelism: 1}, false},
		{Params{MemoryKiB: 127, Iterations: 1, Parallelism: 16}, false},
		{Params{MemoryKiB: 1<<20 + 1, Iterations: 1, Parallelism: 1}, false},
		{Params{MemoryKiB: 65536, Iterations: 0, Parallelism: 1}, false},
		{Params{MemoryKiB: 65536, Iterations: 17, Parallelism: 1}, false},
		{Params{MemoryKiB: 65536, Iterations: 2, Parallelism: 0}, false},
		{Params{MemoryKiB: 65536, Iterations: 2, Parallelism: 17}, false},
	} {
		if err := tt.p.validate(); (err == nil) != tt.ok {
			t.Errorf("%+v.validate() = %v, want ok %t", tt.p, err, tt.ok)
		}
	}
}
