package fakes

import (
	"sync"
	"time"

	"github.com/arafat-hasan/auth1/internal/app"
)

var _ app.Clock = (*Clock)(nil)

// Clock is a settable clock. It moves only on Set and Advance, and is safe for concurrent use.
// Like the system clock, it reads in UTC, truncated to the microsecond.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a clock set to t, in UTC.
func NewClock(t time.Time) *Clock {
	return &Clock{now: t.UTC()}
}

// Now returns the clock's time, truncated to the microsecond. The clock keeps the exact time it
// was set to, so advances shorter than a microsecond add up.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Truncate(time.Microsecond)
}

// Set moves the clock to t, in UTC.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t.UTC()
}

// Advance moves the clock forward by d. A negative d panics as a test bug; a test that needs the
// clock to step back, to model skew, uses Set.
func (c *Clock) Advance(d time.Duration) {
	if d < 0 {
		panic("fakes: Clock.Advance with a negative duration")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
