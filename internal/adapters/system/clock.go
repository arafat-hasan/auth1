package system

import (
	"time"

	"github.com/arafat-hasan/auth1/internal/app"
)

var _ app.Clock = Clock{}

// Clock is the system wall clock.
type Clock struct{}

// Now returns the current time in UTC, truncated to the microsecond: PostgreSQL's timestamptz
// stores microseconds, so a time that goes through the database comes back equal. UTC strips the
// monotonic reading, which is intended: these times are stored and compared with stored times.
func (Clock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond)
}
