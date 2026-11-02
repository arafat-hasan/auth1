package crypto_test

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
)

// wantReloads is how many times TestReloadDuringSealOpen swaps the keyring, and reloadDeadline
// bounds it on a slow host.
const (
	wantReloads    = 20
	reloadDeadline = 30 * time.Second
)

// TestReloadDuringSealOpen is R-1 (#69): the field keyring file is swapped back and forth while
// many goroutines seal and open. No call may see a half-loaded keyring: every Open of a ciphertext
// sealed under a key that stays in the keyring succeeds, and every Seal uses one of its keys. Run
// under -race (make test). The swapping is driven by a count of reloads, not a time window, so a
// loaded host slows the test down instead of failing it.
func TestReloadDuringSealOpen(t *testing.T) {
	t.Parallel()
	ringA := keyringYAML(entry{1, 1, "active"}, entry{2, 50, "decrypt"})
	ringB := keyringYAML(entry{1, 1, "decrypt"}, entry{2, 50, "active"})
	logs := &logBuffer{}
	w, path := watch(t, ringA, time.Millisecond, logs)
	f := crypto.NewFieldCrypto(w)

	// Ciphertexts under each key, sealed before the swapping starts.
	prepared := map[uint16][]byte{
		1: mustSeal(t, crypto.NewFieldCrypto(mustKeyring(t, entry{1, 1, "active"})), place, []byte("under 1")),
		2: mustSeal(t, crypto.NewFieldCrypto(mustKeyring(t, entry{2, 50, "active"})), place, []byte("under 2")),
	}

	// The workers run until the swapper has seen every reload, or the deadline passes.
	ctx, cancel := context.WithTimeout(context.Background(), reloadDeadline)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() {
		defer cancel()
		// Not the test's goroutine, so a failure is reported with t.Error, not t.Fatal.
		for i := range wantReloads {
			ring := ringB
			if i%2 == 1 {
				ring = ringA
			}
			if err := replaceFile(path, ring); err != nil {
				t.Errorf("swap the keyring file: %v", err)
				return
			}
			// Wait for the watcher to load this file before writing the next, so that every
			// write is a reload.
			for strings.Count(logs.String(), "keyring reloaded") <= i {
				if ctx.Err() != nil {
					t.Errorf("only %d of %d reloads within %s", i, wantReloads, reloadDeadline)
					return
				}
				time.Sleep(time.Millisecond)
			}
		}
	})
	var ops atomic.Int64
	for g := range 32 {
		wg.Go(func() {
			plaintext := []byte(strconv.Itoa(g))
			for ctx.Err() == nil {
				ct, err := f.Seal(place, plaintext)
				if err != nil {
					t.Errorf("Seal: %v", err)
					return
				}
				if kid := headerKid(ct); kid != 1 && kid != 2 {
					t.Errorf("sealed under key %d", kid)
					return
				}
				if got, err := f.Open(place, ct); err != nil || !bytes.Equal(got, plaintext) {
					t.Errorf("Open of a fresh ciphertext = %q, %v", got, err)
					return
				}
				for kid, ct := range prepared {
					if _, err := f.Open(place, ct); err != nil {
						t.Errorf("Open under key %d: %v", kid, err)
						return
					}
				}
				ops.Add(1)
			}
		})
	}
	wg.Wait()

	reloads := strings.Count(logs.String(), "keyring reloaded")
	t.Logf("%d seal-open rounds across %d reloads", ops.Load(), reloads)
	if reloads != wantReloads {
		t.Errorf("%d reloads, want %d", reloads, wantReloads)
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("a valid file failed to load: %s", logs)
	}
}
