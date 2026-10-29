package app

import "crypto"

// PublicKey is one published signing key (TDD-04 §5.2).
type PublicKey struct {
	Kid string           // RFC 7638 thumbprint
	Alg string           // RS256 or ES256; the only algorithm a token with this kid may use
	Key crypto.PublicKey // *rsa.PublicKey or *ecdsa.PublicKey
}

// PublicKeys is the published key set: the JWKS, and the keys a token may be verified with.
type PublicKeys interface {
	// Key returns the published key kid, or false when no published key has that kid.
	Key(kid string) (PublicKey, bool)
	// Published returns the published keys in the keyring file's order, or false before the
	// keyring's first sync with the database, when the set is not known.
	Published() ([]PublicKey, bool)
}
