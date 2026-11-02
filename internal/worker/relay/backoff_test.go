package relay_test

import (
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/worker/relay"
)

// TestBackoff checks TDD-06 §3.1: exponential from 1 s to 5 min, with ±20% jitter.
func TestBackoff(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		attempt int
		jitter  float64
		want    time.Duration
	}{
		{1, 0, time.Second},
		{2, 0, 2 * time.Second},
		{9, 0, 256 * time.Second},
		{10, 0, 5 * time.Minute},
		{20, 0, 5 * time.Minute},
		{1000, 0, 5 * time.Minute},
		{1, -1, 800 * time.Millisecond},
		{1, 1, 1200 * time.Millisecond},
		{3, 0.5, 4400 * time.Millisecond},
		{10, 1, 6 * time.Minute},
		{10, -1, 4 * time.Minute},
		{0, 0, time.Second},
	} {
		if got := relay.Backoff(tc.attempt, tc.jitter); got != tc.want {
			t.Errorf("Backoff(%d, %v) = %v, want %v", tc.attempt, tc.jitter, got, tc.want)
		}
	}
}
