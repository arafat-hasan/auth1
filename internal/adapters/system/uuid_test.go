package system_test

import (
	"bytes"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/adapters/system"
)

func TestUUIDv7Format(t *testing.T) {
	t.Parallel()
	for range 1000 {
		id := system.UUIDv7{}.New()
		if id.Version() != 7 || id.Variant() != uuid.RFC4122 {
			t.Fatalf("%v: version %d, variant %v; want 7, RFC 4122 (RFC 9562)", id, id.Version(), id.Variant())
		}
	}
}

// More ids than rand_a has values (4096), most of them in a shared millisecond, still strictly
// increase.
func TestUUIDv7Increasing(t *testing.T) {
	t.Parallel()
	const n = 100_000
	ids := make([]uuid.UUID, n)
	for i := range ids {
		ids[i] = system.UUIDv7{}.New()
	}
	sharedMilli := false
	for i := 1; i < n; i++ {
		if bytes.Compare(ids[i-1][:], ids[i][:]) >= 0 {
			t.Fatalf("id %d = %v, not after %v", i, ids[i], ids[i-1])
		}
		if bytes.Equal(ids[i-1][:6], ids[i][:6]) {
			sharedMilli = true
		}
	}
	if !sharedMilli {
		t.Error("no two consecutive ids share a millisecond; sub-millisecond ordering not exercised")
	}
}

// Ids from several goroutines are unique, and each goroutine's ids strictly increase.
func TestUUIDv7Concurrent(t *testing.T) {
	t.Parallel()
	const goroutines, each = 8, 10_000
	got := make([][]uuid.UUID, goroutines)
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			ids := make([]uuid.UUID, each)
			for i := range ids {
				ids[i] = system.UUIDv7{}.New()
			}
			got[g] = ids
		})
	}
	wg.Wait()

	seen := make(map[uuid.UUID]bool, goroutines*each)
	for g, ids := range got {
		for i, id := range ids {
			if i > 0 && bytes.Compare(ids[i-1][:], id[:]) >= 0 {
				t.Fatalf("goroutine %d: id %d = %v, not after %v", g, i, id, ids[i-1])
			}
			if seen[id] {
				t.Fatalf("duplicate id %v", id)
			}
			seen[id] = true
		}
	}
}
