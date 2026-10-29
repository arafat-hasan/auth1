package app

import (
	"context"
	"time"
)

// SigningKeyRecord names a signing key for SigningKeyStore.Publish.
type SigningKeyRecord struct {
	Kid string // RFC 7638 thumbprint
	Alg string // RS256 or ES256
}

// SigningKeyStore keeps the publication times of the signing keys (TDD-04 §5.2), shared by every
// replica. Every time it compares or stores is the database's clock, never a replica's, so clock
// skew between replicas cannot shorten the wait of I-14.
type SigningKeyStore interface {
	// Publish records the first publication of each key, now; a key already recorded keeps its
	// time (step 1).
	Publish(ctx context.Context, keys []SigningKeyRecord) error
	// Activate reports whether kid was first published at least minPublish ago. When it was, kid
	// may sign: its activated_at is set to now and its retired_at is cleared (step 2).
	Activate(ctx context.Context, kid string, minPublish time.Duration) (bool, error)
	// KeepSigning records that kid, the previously active key, still signs while the active key
	// waits: its activated_at is set to now and its retired_at is cleared (step 2).
	KeepSigning(ctx context.Context, kid string) error
	// LatestActivated returns the key among kids with the latest activated_at, or "" when none of
	// them has signed: the key that signed last, the previously active key of step 2.
	LatestActivated(ctx context.Context, kids []string) (string, error)
	// Retire sets retired_at, now, for each of kids that has none (step 3).
	Retire(ctx context.Context, kids []string) error
	// Retiring returns those of kids still in the JWKS window: retired_at null, or less than
	// window ago.
	Retiring(ctx context.Context, kids []string, window time.Duration) ([]string, error)
}
