package argon2id_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/crypto/argon2id"
	"github.com/arafat-hasan/auth1/internal/app"
)

var _ app.PasswordHasher = (*argon2id.Hasher)(nil)

func TestVerifyDummyFalse(t *testing.T) {
	t.Parallel()
	h := newHasher(t, small, peppers(t, pepper{1, 1, crypto.StateActive}))
	for _, pw := range [][]byte{nil, {}, []byte("pw"), make([]byte, 128)} {
		if ok, err := h.VerifyDummy(t.Context(), pw); ok || err != nil {
			t.Errorf("VerifyDummy(%q) = %t, %v; want false, nil", pw, ok, err)
		}
	}
}

// TestVerifyDummyAfterKeyRemoved: the dummy was made under a pepper key that a reload has since
// removed; VerifyDummy still does the work and answers false, with no error.
func TestVerifyDummyAfterKeyRemoved(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keyring.yaml")
	if err := os.WriteFile(path, keyringYAML(pepper{1, 1, crypto.StateActive}), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := crypto.NewWatchedKeyring(path, crypto.StateVerify, slog.New(slog.DiscardHandler), crypto.WithInterval(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	h := newHasher(t, small, w)
	if err := os.WriteFile(path, keyringYAML(pepper{2, 50, crypto.StateActive}), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	go func() { _ = w.Run(ctx) }()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, ok := w.Current().Lookup(1); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the keyring was not reloaded")
		}
		time.Sleep(time.Millisecond)
	}
	if ok, err := h.VerifyDummy(ctx, []byte("pw")); ok || err != nil {
		t.Errorf("VerifyDummy = %t, %v; want false, nil", ok, err)
	}
}

// TestDummyTiming: verifying against the dummy takes as long as against a real hash, within 20%
// (TDD-03 §1.4 step 4). Real and dummy verifications are interleaved, so load on the machine
// affects both alike, and their medians are compared. Argon2id's core is assembly, which the race
// detector does not instrument, so -race slows both alike too. A noisy neighbour can still skew
// one attempt; the test passes if one of three is within 20%, and logs every attempt.
func TestDummyTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	params := argon2id.Params{MemoryKiB: 4096, Iterations: 2, Parallelism: 1}
	h := newHasher(t, params, peppers(t, pepper{1, 1, crypto.StateActive}))
	phc, kid, err := h.Hash(t.Context(), []byte("real password"))
	if err != nil {
		t.Fatal(err)
	}
	verifyReal := func() {
		if ok, _, err := h.Verify(t.Context(), phc, kid, []byte("a wrong guess")); ok || err != nil {
			t.Fatalf("Verify = %t, %v", ok, err)
		}
	}
	verifyDummy := func() {
		if ok, err := h.VerifyDummy(t.Context(), []byte("a wrong guess")); ok || err != nil {
			t.Fatalf("VerifyDummy = %t, %v", ok, err)
		}
	}
	const rounds, attempts = 41, 3
	timed := func(f func()) time.Duration {
		start := time.Now()
		f()
		return time.Since(start)
	}
	verifyReal()
	verifyDummy()
	for attempt := 1; attempt <= attempts; attempt++ {
		var rs, ds []time.Duration
		for range rounds {
			rs = append(rs, timed(verifyReal))
			ds = append(ds, timed(verifyDummy))
		}
		r, d := median(rs), median(ds)
		ratio := float64(d) / float64(r)
		t.Logf("attempt %d: median real %s, dummy %s, ratio %.3f", attempt, r, d, ratio)
		if ratio >= 0.8 && ratio <= 1.2 {
			return
		}
	}
	t.Errorf("dummy verification is not within 20%% of a real one in %d attempts", attempts)
}

func median(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	return s[len(s)/2]
}
