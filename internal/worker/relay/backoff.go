package relay

import (
	"math"
	"time"
)

// The retry delays of TDD-06 §3.1, which deliveries share: from backoffFirst, doubling up to
// backoffLast, each scaled by up to ±backoffJitter.
const (
	backoffFirst  = time.Second
	backoffLast   = 5 * time.Minute
	backoffJitter = 0.2
)

// Backoff returns the delay before the retry that follows attempt (from 1): backoffFirst doubled
// attempt-1 times, at most backoffLast, scaled by 1 + 0.2×jitter, jitter in [-1, 1].
func Backoff(attempt int, jitter float64) time.Duration {
	d := backoffLast
	if shift := max(attempt, 1) - 1; shift < 16 {
		d = min(backoffFirst<<shift, backoffLast)
	}
	return time.Duration(math.Round(float64(d) * (1 + backoffJitter*jitter)))
}
