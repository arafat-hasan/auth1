package fakes_test

import (
	"bytes"
	"slices"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

func TestIDsFormat(t *testing.T) {
	t.Parallel()
	ids := fakes.NewIDs()
	for range 1000 {
		id := ids.New()
		if id.Version() != 7 || id.Variant() != uuid.RFC4122 {
			t.Fatalf("%v: version %d, variant %v; want 7, RFC 4122 (RFC 9562)", id, id.Version(), id.Variant())
		}
	}
}

func TestIDsIncreasing(t *testing.T) {
	t.Parallel()
	ids := fakes.NewIDs()
	prev := ids.New()
	for i := range 1000 {
		id := ids.New()
		if bytes.Compare(prev[:], id[:]) >= 0 {
			t.Fatalf("id %d = %v, not after %v", i+2, id, prev)
		}
		prev = id
	}
}

func TestIDsDeterministic(t *testing.T) {
	t.Parallel()
	a, b := fakes.NewIDs(), fakes.NewIDs()
	var fromA, fromB, predicted []uuid.UUID
	for n := 1; n <= 100; n++ {
		fromA = append(fromA, a.New())
		fromB = append(fromB, b.New())
		predicted = append(predicted, fakes.ID(n))
	}
	if diff := cmp.Diff(fromA, fromB); diff != "" {
		t.Errorf("two generators differ (-a +b):\n%s", diff)
	}
	if diff := cmp.Diff(predicted, fromA); diff != "" {
		t.Errorf("ID(n) differs from the nth New() (-ID +New):\n%s", diff)
	}
	// 2026-01-01T00:00:00Z plus 1 ms, version 7, rand_a 0, variant 10, rand_b 1.
	if got, want := fakes.ID(1).String(), "019b76da-a801-7000-8000-000000000001"; got != want {
		t.Errorf("ID(1) = %s, want %s", got, want)
	}
}

func TestIDPanicsBelowOne(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("ID(%d) did not panic", n)
				}
			}()
			fakes.ID(n)
		}()
	}
}

// Ids taken from several goroutines are exactly ID(1)…ID(N), each once.
func TestIDsConcurrent(t *testing.T) {
	t.Parallel()
	const goroutines, each = 8, 1000
	ids := fakes.NewIDs()
	var (
		mu  sync.Mutex
		got []uuid.UUID
		wg  sync.WaitGroup
	)
	for range goroutines {
		wg.Go(func() {
			mine := make([]uuid.UUID, each)
			for i := range mine {
				mine[i] = ids.New()
			}
			mu.Lock()
			got = append(got, mine...)
			mu.Unlock()
		})
	}
	wg.Wait()

	slices.SortFunc(got, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	want := make([]uuid.UUID, goroutines*each)
	for i := range want {
		want[i] = fakes.ID(i + 1)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ids differ from ID(1)…ID(%d) (-want +got):\n%s", len(want), diff)
	}
}
