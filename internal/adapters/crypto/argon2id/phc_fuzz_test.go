package argon2id

import "testing"

// FuzzParsePHC: parsePHC never panics, and a string it accepts encodes back to itself, so there is
// one spelling of each hash (TDD-08 §9).
func FuzzParsePHC(f *testing.F) {
	f.Add(testPHC(Params{MemoryKiB: 65536, Iterations: 2, Parallelism: 1}).encode())
	f.Add(testPHC(Params{MemoryKiB: 1 << 20, Iterations: 16, Parallelism: 16}).encode())
	f.Add("$argon2id$v=19$m=1048577,t=2,p=1$AQIDBAUGBwgJCgsMDQ4PEA$oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8")
	f.Add("$argon2id$v=19$m=65536,t=2,p=1$AQIDBAUGBwgJCgsMDQ4PEA==$oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8")
	f.Add("$argon2i$v=19$m=65536,t=2,p=1$$")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		v, err := parsePHC(s)
		if err != nil {
			return
		}
		if got := v.encode(); got != s {
			t.Errorf("parsePHC(%q) re-encodes as %q", s, got)
		}
	})
}
