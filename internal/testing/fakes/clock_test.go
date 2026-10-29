package fakes_test

import (
	"sync"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// start has a sub-microsecond part, which Now drops: a clock set to start reads startMicro.
var (
	start      = time.Date(2026, 3, 14, 15, 9, 26, 535897932, time.UTC)
	startMicro = time.Date(2026, 3, 14, 15, 9, 26, 535897000, time.UTC)
)

func TestClock(t *testing.T) {
	t.Parallel()
	other := time.Date(2027, 1, 2, 3, 4, 5, 6000, time.UTC)
	for _, tc := range []struct {
		name string
		op   func(c *fakes.Clock)
		want time.Time
	}{
		{"untouched", func(*fakes.Clock) {}, startMicro},
		{"set", func(c *fakes.Clock) { c.Set(other) }, other},
		{"set sub-microsecond", func(c *fakes.Clock) { c.Set(other.Add(999)) }, other},
		{"advance zero", func(c *fakes.Clock) { c.Advance(0) }, startMicro},
		{"advance 90s", func(c *fakes.Clock) { c.Advance(90 * time.Second) }, startMicro.Add(90 * time.Second)},
		{"advance 1µs", func(c *fakes.Clock) { c.Advance(time.Microsecond) }, startMicro.Add(time.Microsecond)},
		// start is 932 ns past its microsecond: 68 ns more reaches the next one, 67 ns does not.
		{"advance 1ns", func(c *fakes.Clock) { c.Advance(time.Nanosecond) }, startMicro},
		{"advance 67ns", func(c *fakes.Clock) { c.Advance(67 * time.Nanosecond) }, startMicro},
		{"advance 68ns", func(c *fakes.Clock) { c.Advance(68 * time.Nanosecond) }, startMicro.Add(time.Microsecond)},
		{"advance 68 × 1ns", func(c *fakes.Clock) {
			for range 68 {
				c.Advance(time.Nanosecond)
			}
		}, startMicro.Add(time.Microsecond)},
		{"set back", func(c *fakes.Clock) { c.Set(startMicro.Add(-time.Hour)) }, startMicro.Add(-time.Hour)},
		{"set then advance", func(c *fakes.Clock) { c.Set(other); c.Advance(time.Hour) }, other.Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := fakes.NewClock(start)
			tc.op(c)
			first, second := c.Now(), c.Now()
			if !first.Equal(tc.want) || !second.Equal(tc.want) {
				t.Errorf("Now() = %v, then %v; want %v both times", first, second, tc.want)
			}
		})
	}
}

// A time in another zone reads as the same instant, in UTC, to the microsecond.
func TestClockUTC(t *testing.T) {
	t.Parallel()
	given := time.Date(2026, 5, 1, 12, 0, 0, 123456789, time.FixedZone("x", 5*3600))
	want := time.Date(2026, 5, 1, 7, 0, 0, 123456000, time.UTC)
	c := fakes.NewClock(given)
	check := func(op string) {
		t.Helper()
		got := c.Now()
		if got.Location() != time.UTC || !got.Equal(want) {
			t.Errorf("after %s: Now() = %v, want %v", op, got, want)
		}
	}
	check("NewClock")
	c.Set(given)
	check("Set")
}

func TestClockNegativeAdvancePanics(t *testing.T) {
	t.Parallel()
	c := fakes.NewClock(start)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Advance(-1ns) did not panic")
			}
		}()
		c.Advance(-time.Nanosecond)
	}()
	if got := c.Now(); !got.Equal(startMicro) {
		t.Errorf("Now() = %v after the panic, want %v", got, startMicro)
	}
}

func TestClockConcurrent(t *testing.T) {
	t.Parallel()
	const goroutines, each = 8, 1000
	c := fakes.NewClock(start)
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range each {
				c.Advance(time.Millisecond)
				_ = c.Now()
			}
		})
	}
	wg.Wait()
	if got, want := c.Now(), startMicro.Add(goroutines*each*time.Millisecond); !got.Equal(want) {
		t.Errorf("Now() = %v, want %v", got, want)
	}
}
