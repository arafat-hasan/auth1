package keyring

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestReloadDuringParallelSigning is R-1: the keyring file is swapped while tokens are signed in
// parallel. No signer sees half a reload (each token's kid names the key that signed it), and
// every token signed before or during the swaps still validates against the published set.
func TestReloadDuringParallelSigning(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	ec := ecKeys()[0]
	k1, k2 := kidOf(t, r[0]), kidOf(t, ec)
	before := []spec{{alg: AlgRS256, state: StateActive, key: r[0]}, {alg: AlgES256, state: StateNext, key: ec}}
	after := []spec{{alg: AlgRS256, state: StateRetired, key: r[0]}, {alg: AlgES256, state: StateActive, key: ec}}
	e.write(t, before)
	k := e.replica(t)
	e.promotable(t, k1)
	e.promotable(t, k2)
	reload(t, k)

	const signers = 8
	var (
		stop   atomic.Bool
		wg     sync.WaitGroup
		tokens = make([][]string, signers)
		errs   = make([]error, signers)
	)
	for i := range signers {
		wg.Go(func() {
			for !stop.Load() {
				tok, err := k.Sign([]byte(`{"sub":"x"}`), "at+jwt")
				if err != nil {
					errs[i] = err
					return
				}
				tokens[i] = append(tokens[i], tok)
			}
		})
	}
	for i := range 50 {
		if i%2 == 0 {
			e.write(t, after)
		} else {
			e.write(t, before)
		}
		reload(t, k)
	}
	stop.Store(true)
	wg.Wait()

	seen := map[string]int{}
	total := 0
	for i := range signers {
		if errs[i] != nil {
			t.Fatalf("signer %d: %v", i, errs[i])
		}
		for _, tok := range tokens[i] {
			seen[verify(t, k, tok)]++
			total++
		}
	}
	if seen[k1] == 0 || seen[k2] == 0 {
		t.Errorf("signed by %v over %d tokens, want both keys to have signed", seen, total)
	}
}
