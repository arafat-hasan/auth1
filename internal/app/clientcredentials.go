package app

import (
	"context"
	"time"
)

// ClientAssertions records the jti of each client assertion accepted (TDD-05 §2, client_assertions).
type ClientAssertions interface {
	// Record stores (clientID, jti) until expiresAt and reports whether it is new. Of concurrent
	// records of one pair, exactly one is new: the insert is the one statement that decides a
	// replay.
	Record(ctx context.Context, clientID, jti string, expiresAt time.Time) (fresh bool, err error)
}
