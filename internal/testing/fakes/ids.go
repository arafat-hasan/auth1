package fakes

import (
	"encoding/binary"
	"sync"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
)

var _ app.IDGenerator = (*IDs)(nil)

// idBase is 2026-01-01T00:00:00Z in Unix milliseconds: the nth id's unix_ts_ms is idBase plus n.
const idBase = 1_767_225_600_000

// IDs makes the ids ID(1), ID(2), … in order. It is safe for concurrent use.
type IDs struct {
	mu sync.Mutex
	n  int
}

// NewIDs returns a generator whose first id is ID(1).
func NewIDs() *IDs {
	return &IDs{}
}

// New returns the next id.
func (g *IDs) New() uuid.UUID {
	g.mu.Lock()
	g.n++
	n := g.n
	g.mu.Unlock()
	return ID(n)
}

// ID returns the nth id (n ≥ 1) that a fresh NewIDs gives, so a test can predict ids. It is a
// valid UUIDv7 (RFC 9562 variant) with no randomness: unix_ts_ms is 2026-01-01T00:00:00Z plus n
// milliseconds, rand_a is 0 and rand_b is n. ID(n) < ID(n+1). An n below 1 panics.
func ID(n int) uuid.UUID {
	if n < 1 {
		panic("fakes: ID(n) needs n >= 1")
	}
	var id uuid.UUID
	ms := uint64(idBase) + uint64(n)
	for i := range 6 {
		id[i] = byte(ms >> (40 - 8*i))
	}
	id[6] = 0x70 // version 7; rand_a is 0
	binary.BigEndian.PutUint64(id[8:], uint64(n))
	id[8] = id[8]&0x3f | 0x80 // variant 10
	return id
}
