package app

import "time"

// Clock gives the wall time in UTC (TDD-01 §1), for timestamps that are stored or compared with
// stored ones: expiries, created_at. Now is truncated to the microsecond, the precision of
// PostgreSQL's timestamptz, so a time that goes through the database comes back equal.
// Elapsed-time measurement (latency, timeouts) keeps using time.Since and does not go through Clock.
type Clock interface {
	Now() time.Time
}
