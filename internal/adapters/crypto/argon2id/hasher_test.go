package argon2id_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/crypto/argon2id"
	"github.com/arafat-hasan/auth1/internal/app"
)

// small are parameters that hash in well under a millisecond, for the tests that are not about
// cost.
var small = argon2id.Params{MemoryKiB: 64, Iterations: 1, Parallelism: 1}

// pepper is one pepper keyring entry.
type pepper struct {
	id    int
	first byte // the key is 32 bytes counting up from first
	state string
}

func keyBytes(first byte) []byte {
	b := make([]byte, crypto.KeySize)
	for i := range b {
		b[i] = first + byte(i)
	}
	return b
}

func keyringYAML(entries ...pepper) []byte {
	var b strings.Builder
	b.WriteString("keys:\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "  - id: %d\n    key: %s\n    state: %s\n", e.id, base64.StdEncoding.EncodeToString(keyBytes(e.first)), e.state)
	}
	return []byte(b.String())
}

func peppers(t testing.TB, entries ...pepper) *crypto.Keyring {
	t.Helper()
	k, err := crypto.ParseKeyring(keyringYAML(entries...), crypto.StateVerify)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// runWatched follows w's file until the test ends, and waits for it to stop.
func runWatched(t *testing.T, w *crypto.WatchedKeyring) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = w.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func newHasher(t testing.TB, params argon2id.Params, src crypto.KeyringSource) *argon2id.Hasher {
	t.Helper()
	h, err := argon2id.New(argon2id.Options{Params: params, MaxConcurrent: 4, QueueTimeout: time.Second, Peppers: src})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func TestHashVerify(t *testing.T) {
	t.Parallel()
	h := newHasher(t, small, peppers(t, pepper{1, 1, crypto.StateActive}))
	phc, kid, err := h.Hash(t.Context(), []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Errorf("phc = %q", phc)
	}
	ok, rehash, err := h.Verify(t.Context(), phc, kid, []byte("correct horse battery staple"))
	if err != nil || !ok || rehash {
		t.Errorf("Verify(right) = %t, %t, %v; want true, false, nil", ok, rehash, err)
	}
	ok, rehash, err = h.Verify(t.Context(), phc, kid, []byte("correct horse battery stapler"))
	if err != nil || ok || rehash {
		t.Errorf("Verify(wrong) = %t, %t, %v; want false, false, nil", ok, rehash, err)
	}
	again, _, err := h.Hash(t.Context(), []byte("correct horse battery staple"))
	if err != nil || again == phc {
		t.Errorf("a second hash of the same password is %q (%v); want a fresh salt", again, err)
	}
}

// TestPepperKidFormat: pepper_kid is the key id's plain decimal text; WP-30 stores it as is.
func TestPepperKidFormat(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		id   int
		want string
	}{{3, "3"}, {10, "10"}, {65535, "65535"}} {
		h := newHasher(t, small, peppers(t, pepper{tt.id, 1, crypto.StateActive}))
		_, kid, err := h.Hash(t.Context(), []byte("pw"))
		if err != nil || kid != tt.want {
			t.Errorf("key id %d: kid = %q, %v; want %q", tt.id, kid, err, tt.want)
		}
	}
}

// TestNFKC: passwords are compared after NFKC normalisation (TDD-03 §1.1).
func TestNFKC(t *testing.T) {
	t.Parallel()
	h := newHasher(t, small, peppers(t, pepper{1, 1, crypto.StateActive}))
	for _, tt := range []struct{ stored, given string }{
		{"ﬁle", "file"},   // the ligature ﬁ
		{"café", "café"}, // composed and decomposed é
		{"１２３", "123"},    // full-width digits
	} {
		phc, kid, err := h.Hash(t.Context(), []byte(tt.stored))
		if err != nil {
			t.Fatal(err)
		}
		if ok, _, err := h.Verify(t.Context(), phc, kid, []byte(tt.given)); err != nil || !ok {
			t.Errorf("%q does not verify against %q: %t, %v", tt.given, tt.stored, ok, err)
		}
	}
}

// TestHashKeepsPassword: the caller's password is not modified, even when it is already NFKC.
func TestHashKeepsPassword(t *testing.T) {
	t.Parallel()
	h := newHasher(t, small, peppers(t, pepper{1, 1, crypto.StateActive}))
	pw := []byte("already normal")
	phc, kid, err := h.Hash(t.Context(), pw)
	if err != nil || string(pw) != "already normal" {
		t.Fatalf("Hash changed the password to %q (%v)", pw, err)
	}
	if _, _, err := h.Verify(t.Context(), phc, kid, pw); err != nil || string(pw) != "already normal" {
		t.Fatalf("Verify changed the password to %q (%v)", pw, err)
	}
}

func TestNeedsRehash(t *testing.T) {
	t.Parallel()
	old := newHasher(t, small, peppers(t, pepper{1, 1, crypto.StateActive}, pepper{2, 50, crypto.StateVerify}))
	phc, kid, err := old.Hash(t.Context(), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		params argon2id.Params
		keys   *crypto.Keyring
		want   bool
	}{
		{"same", small, peppers(t, pepper{1, 1, crypto.StateActive}), false},
		{"memory", argon2id.Params{MemoryKiB: 128, Iterations: 1, Parallelism: 1}, peppers(t, pepper{1, 1, crypto.StateActive}), true},
		{"iterations", argon2id.Params{MemoryKiB: 64, Iterations: 2, Parallelism: 1}, peppers(t, pepper{1, 1, crypto.StateActive}), true},
		{"parallelism", argon2id.Params{MemoryKiB: 64, Iterations: 1, Parallelism: 2}, peppers(t, pepper{1, 1, crypto.StateActive}), true},
		{"pepper rotated", small, peppers(t, pepper{1, 1, crypto.StateVerify}, pepper{2, 50, crypto.StateActive}), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHasher(t, tt.params, tt.keys)
			ok, rehash, err := h.Verify(t.Context(), phc, kid, []byte("pw"))
			if err != nil || !ok || rehash != tt.want {
				t.Errorf("Verify = %t, %t, %v; want true, %t, nil", ok, rehash, err, tt.want)
			}
			ok, rehash, err = h.Verify(t.Context(), phc, kid, []byte("wrong"))
			if err != nil || ok || rehash {
				t.Errorf("Verify(wrong) = %t, %t, %v; want false, false, nil", ok, rehash, err)
			}
		})
	}
}

// TestVerifyUnknownPepperKid: a pepper_kid the keyring does not hold, or not in canonical decimal,
// is ErrPepperKeyUnknown, never a wrong password.
func TestVerifyUnknownPepperKid(t *testing.T) {
	t.Parallel()
	h := newHasher(t, small, peppers(t, pepper{3, 1, crypto.StateActive}))
	phc, _, err := h.Hash(t.Context(), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kid := range []string{"9", "03", "+3", " 3", "3 ", "0", "65536", "-3", "0x3", ""} {
		if ok, rehash, err := h.Verify(t.Context(), phc, kid, []byte("pw")); !errors.Is(err, app.ErrPepperKeyUnknown) || ok || rehash {
			t.Errorf("Verify(kid %q) = %t, %t, %v; want ErrPepperKeyUnknown", kid, ok, rehash, err)
		}
	}
}

func TestVerifyInvalidPHC(t *testing.T) {
	t.Parallel()
	h := newHasher(t, small, peppers(t, pepper{1, 1, crypto.StateActive}))
	for _, phc := range []string{"", "$2a$10$bcrypt", "$argon2id$v=19$m=2000000,t=1,p=1$AQIDBAUGBwgJCgsMDQ4PEA$oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8"} {
		if ok, _, err := h.Verify(t.Context(), phc, "1", []byte("pw")); !errors.Is(err, app.ErrPasswordHashInvalid) || ok {
			t.Errorf("Verify(%q) = %t, %v; want ErrPasswordHashInvalid", phc, ok, err)
		}
	}
}

func TestNewRefuses(t *testing.T) {
	t.Parallel()
	keys := peppers(t, pepper{1, 1, crypto.StateActive})
	valid := argon2id.Options{Params: small, MaxConcurrent: 1, QueueTimeout: time.Millisecond, Peppers: keys}
	for _, tt := range []struct {
		name   string
		change func(*argon2id.Options)
	}{
		{"memory below 8 KiB per lane", func(o *argon2id.Options) { o.Params.MemoryKiB = 7 }},
		{"memory above 1 GiB", func(o *argon2id.Options) { o.Params.MemoryKiB = 1<<20 + 1 }},
		{"iterations 0", func(o *argon2id.Options) { o.Params.Iterations = 0 }},
		{"iterations 17", func(o *argon2id.Options) { o.Params.Iterations = 17 }},
		{"parallelism 0", func(o *argon2id.Options) { o.Params.Parallelism = 0 }},
		{"parallelism 17", func(o *argon2id.Options) { o.Params.Parallelism = 17 }},
		{"max concurrent 0", func(o *argon2id.Options) { o.MaxConcurrent = 0 }},
		{"queue timeout 0", func(o *argon2id.Options) { o.QueueTimeout = 0 }},
		{"no peppers", func(o *argon2id.Options) { o.Peppers = nil }},
	} {
		o := valid
		tt.change(&o)
		if _, err := argon2id.New(o); err == nil {
			t.Errorf("%s: New accepted it", tt.name)
		}
	}
	if _, err := argon2id.New(valid); err != nil {
		t.Errorf("New(valid): %v", err)
	}
}

// TestHashDuringReload: the pepper keyring is swapped while hashes run; every hash names the key
// it was made under, so each verifies (R-1).
func TestHashDuringReload(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keyring.yaml")
	a := keyringYAML(pepper{1, 1, crypto.StateActive}, pepper{2, 50, crypto.StateVerify})
	b := keyringYAML(pepper{1, 1, crypto.StateVerify}, pepper{2, 50, crypto.StateActive})
	write := func(data []byte) {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			t.Error(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Error(err)
		}
	}
	write(a)
	w, err := crypto.NewWatchedKeyring(path, crypto.StateVerify, slog.New(slog.DiscardHandler), crypto.WithInterval(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	runWatched(t, w)
	ctx := t.Context()
	h := newHasher(t, small, w)
	stop := make(chan struct{})
	var swapper sync.WaitGroup
	swapper.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
				write([][]byte{a, b}[i%2])
			}
		}
	})
	var hashers sync.WaitGroup
	kids := make(chan string, 4*50)
	for range 4 {
		hashers.Go(func() {
			for range 50 {
				phc, kid, err := h.Hash(ctx, []byte("pw"))
				if err != nil {
					t.Error(err)
					return
				}
				if ok, _, err := h.Verify(ctx, phc, kid, []byte("pw")); err != nil || !ok {
					t.Errorf("Verify after reload = %t, %v", ok, err)
				}
				kids <- kid
			}
		})
	}
	hashers.Wait()
	close(stop)
	swapper.Wait()
	close(kids)
	seen := map[string]bool{}
	for k := range kids {
		seen[k] = true
	}
	t.Logf("kids seen: %v", seen)
}

// TestSecretsNotLeaked: no error, and no formatting or logging of the hasher, shows the password,
// the pepper, the salt or the hash (G-6).
func TestSecretsNotLeaked(t *testing.T) {
	t.Parallel()
	keys := peppers(t, pepper{1, 1, crypto.StateActive})
	h := newHasher(t, small, keys)
	const password = "s3cret-Pa55word"
	phc, kid, err := h.Hash(t.Context(), []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(phc, "$")
	secrets := []string{
		password, parts[4], parts[5],
		base64.StdEncoding.EncodeToString(keyBytes(1)), hex.EncodeToString(keyBytes(1)),
		fmt.Sprintf("%d", keyBytes(1)),
	}
	var outputs []string
	for _, call := range []func() error{
		func() error { _, _, err := h.Verify(t.Context(), phc, "9", []byte(password)); return err },
		func() error { _, _, err := h.Verify(t.Context(), phc[:len(phc)-1], kid, []byte(password)); return err },
		func() error {
			_, _, err := h.Verify(t.Context(), strings.Replace(phc, "m=64", "m=4", 1), kid, []byte(password))
			return err
		},
	} {
		err := call()
		if err == nil {
			t.Fatal("expected an error")
		}
		outputs = append(outputs, err.Error(), fmt.Sprintf("%+v", err))
	}
	var buf strings.Builder
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("hasher", "hasher", h)
	outputs = append(outputs, fmt.Sprintf("%v", h), fmt.Sprintf("%+v", h), fmt.Sprintf("%#v", h),
		fmt.Sprintf("%v", *h), fmt.Sprintf("%+v", *h), buf.String())
	for _, out := range outputs {
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("output %q contains a secret", out)
			}
		}
	}
	if want := "argon2id(m=64,t=1,p=1)"; fmt.Sprint(h) != want {
		t.Errorf("fmt.Sprint(h) = %q, want %q", fmt.Sprint(h), want)
	}
}
