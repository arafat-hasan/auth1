package fakes_test

import (
	"sync"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

var start = time.Date(2026, 3, 14, 15, 9, 26, 535897932, time.UTC)

func TestClock(t *testing.T) {
	t.Parallel()
	other := time.Date(2027, 1, 2, 3, 4, 5, 6, time.UTC)
	for _, tc := range []struct {
		name string
		op   func(c *fakes.Clock)
		want time.Time
	}{
		{"untouched", func(*fakes.Clock) {}, start},
		{"set", func(c *fakes.Clock) { c.Set(other) }, other},
		{"advance zero", func(c *fakes.Clock) { c.Advance(0) }, start},
		{"advance 90s", func(c *fakes.Clock) { c.Advance(90 * time.Second) }, start.Add(90 * time.Second)},
		{"advance 1ns", func(c *fakes.Clock) { c.Advance(time.Nanosecond) }, start.Add(time.Nanosecond)},
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

// A time in another zone is kept as the same instant, in UTC, with its nanoseconds.
func TestClockUTC(t *testing.T) {
	t.Parallel()
	given := time.Date(2026, 5, 1, 12, 0, 0, 123456789, time.FixedZone("x", 5*3600))
	c := fakes.NewClock(given)
	check := func(op string) {
		t.Helper()
		got := c.Now()
		if got.Location() != time.UTC || !got.Equal(given) || got.Nanosecond() != given.Nanosecond() {
			t.Errorf("after %s: Now() = %v, want %v in UTC", op, got, given)
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
	if got := c.Now(); !got.Equal(start) {
		t.Errorf("Now() = %v after the panic, want %v", got, start)
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
	if got, want := c.Now(), start.Add(goroutines*each*time.Millisecond); !got.Equal(want) {
		t.Errorf("Now() = %v, want %v", got, want)
	}
}
