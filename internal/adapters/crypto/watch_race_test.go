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

// TestReloadDuringSealOpen is R-1 (#69): the field keyring file is swapped back and forth while
// many goroutines seal and open. No call may see a half-loaded keyring: every Open of a ciphertext
// sealed under a key that stays in the keyring succeeds, and every Seal uses one of its keys. Run
// under -race (make test).
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() {
		// Not the test's goroutine, so a failed write is reported with t.Error, not t.Fatal.
		for i := 0; ctx.Err() == nil; i++ {
			ring := ringA
			if i%2 == 0 {
				ring = ringB
			}
			if err := replaceFile(path, ring); err != nil {
				t.Errorf("swap the keyring file: %v", err)
				return
			}
			time.Sleep(2 * time.Millisecond)
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
	if reloads < 10 {
		t.Errorf("only %d reloads: the test did not exercise swapping", reloads)
	}
	if strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("a valid file failed to load: %s", logs)
	}
}
