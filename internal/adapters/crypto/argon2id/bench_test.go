package argon2id_test

import (
	"testing"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/crypto/argon2id"
	"github.com/arafat-hasan/auth1/internal/config"
)

// defaultParams are config.Default()'s Argon2id parameters, the ones SDD O-3 tunes towards
// 100–250 ms a hash.
func defaultParams(tb testing.TB) argon2id.Params {
	tb.Helper()
	a := config.Default().Passwords.Argon2
	return argon2id.Params{
		MemoryKiB:   uint32(a.Memory / config.KiB), //nolint:gosec // 64 MiB
		Iterations:  uint32(a.Iterations),          //nolint:gosec // 2
		Parallelism: uint8(a.Parallelism),          //nolint:gosec // 1
	}
}

// BenchmarkHash: one hash at the default parameters; ms/hash is the figure for SDD O-3.
func BenchmarkHash(b *testing.B) {
	h := newHasher(b, defaultParams(b), peppers(b, pepper{1, 1, crypto.StateActive}))
	pw := []byte("correct horse battery staple")
	for b.Loop() {
		if _, _, err := h.Hash(b.Context(), pw); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Milliseconds())/float64(b.N), "ms/hash")
}

// BenchmarkVerify: one verification at the default parameters.
func BenchmarkVerify(b *testing.B) {
	h := newHasher(b, defaultParams(b), peppers(b, pepper{1, 1, crypto.StateActive}))
	pw := []byte("correct horse battery staple")
	phc, kid, err := h.Hash(b.Context(), pw)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if ok, _, err := h.Verify(b.Context(), phc, kid, pw); err != nil || !ok {
			b.Fatal(ok, err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Milliseconds())/float64(b.N), "ms/hash")
}
