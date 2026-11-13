package account_test

import (
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

func TestFactorLimitReached(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	l := account.FactorLimit{Limit: 10, Window: time.Hour}
	for _, tc := range []struct {
		name     string
		failures int
		since    *time.Time
		want     bool
	}{
		{"none", 0, nil, false},
		{"under", 9, at(time.Minute), false},
		{"at", 10, at(time.Minute), true},
		{"over", 11, at(59 * time.Minute), true},
		{"at, window ending now", 10, at(time.Hour), false},
		{"at, window passed", 10, at(2 * time.Hour), false},
		{"count without a start", 10, nil, false},
	} {
		a := account.Account{FactorFailures: tc.failures, FactorFailuresSince: tc.since}
		if got := l.Reached(a, now); got != tc.want {
			t.Errorf("%s: Reached = %v, want %v", tc.name, got, tc.want)
		}
	}
}
