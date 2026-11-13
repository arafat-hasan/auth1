package account

import "time"

// FactorLimit is L-11 (TDD-07 §3): at most Limit second-factor failures per account in a fixed
// window of Window, which starts at the first failure after the last window ended. A correct code
// does not reset it.
type FactorLimit struct {
	Limit  int
	Window time.Duration
}

// Reached reports whether a's failures have reached the limit in a window still running at now:
// the account's second-factor checks are then refused, or, where a refusal would tell too much,
// skipped.
func (l FactorLimit) Reached(a Account, now time.Time) bool {
	since := a.FactorFailuresSince
	return a.FactorFailures >= l.Limit && since != nil && now.Before(since.Add(l.Window))
}
