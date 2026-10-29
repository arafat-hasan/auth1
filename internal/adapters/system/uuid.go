package system

import (
	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
)

var _ app.IDGenerator = UUIDv7{}

// UUIDv7 makes UUIDv7 ids with google/uuid. They strictly increase within the process, across
// goroutines: uuid.NewV7 takes the time and the 12-bit sequence under one lock and never repeats
// or goes back, even past 4096 ids in a millisecond or when the wall clock steps back.
type UUIDv7 struct{}

// New returns a new id.
func (UUIDv7) New() uuid.UUID {
	// NewV7's only error is a failure to read crypto/rand. Since Go 1.24 such a failure crashes
	// the process instead of being returned, so Must never panics.
	return uuid.Must(uuid.NewV7())
}
