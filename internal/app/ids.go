package app

import "github.com/google/uuid"

// IDGenerator makes record ids: UUIDv7 (RFC 9562), strictly increasing within a process (SDD D-2,
// TDD-01 §1). An id is never a capability (I-20): possession of one authorises nothing.
type IDGenerator interface {
	New() uuid.UUID
}
