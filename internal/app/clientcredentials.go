package app

import (
	"context"
	"errors"
	"time"
)

// ClientAssertions records the jti of each client assertion accepted (TDD-05 §2, client_assertions).
type ClientAssertions interface {
	// Record stores (clientID, jti) until expiresAt and reports whether it is new. Of concurrent
	// records of one pair, exactly one is new: the insert is the one statement that decides a
	// replay.
	Record(ctx context.Context, clientID, jti string, expiresAt time.Time) (fresh bool, err error)
}

// ClientKeys finds a service client's public keys (TDD-05 §2): from its jwks_file, or its
// jwks_uri, which it may fetch. Callers call it outside any transaction (G-4).
type ClientKeys interface {
	// Key returns client clientID's usable key kid. A client or kid it does not know is
	// ErrUnknownClientKey; keys it cannot get at all are ErrClientKeysUnavailable.
	Key(ctx context.Context, clientID, kid string) (PublicKey, error)
}

// The failures of ClientKeys.Key.
var (
	// ErrUnknownClientKey: no such client, or no such key after any refetch allowed. The token
	// endpoint answers invalid_client.
	ErrUnknownClientKey = errors.New("client keys: unknown client or kid")
	// ErrClientKeysUnavailable: the client's jwks_uri has no key set cached and could not be
	// fetched. The token endpoint answers 503.
	ErrClientKeysUnavailable = errors.New("client keys: unavailable")
)
