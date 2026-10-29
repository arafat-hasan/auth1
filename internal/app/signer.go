package app

import "github.com/arafat-hasan/auth1/internal/domain"

// ErrNoSigningKey is the failure of TokenSigner.Sign while no key may sign: before the keyring's
// first sync with the database, or while the active key is not yet promotable and no previously
// active key is left in the keyring (TDD-04 §5.2, I-14).
var ErrNoSigningKey = &domain.Error{Code: domain.CodeUnavailable, Detail: "No signing key is available."}

// TokenSigner signs tokens with the signing keyring's current key (TDD-04 §5). The private keys
// never leave it.
type TokenSigner interface {
	// Sign returns payload as a compact JWS whose protected header holds the signing key's alg
	// and kid and the given typ. The alg, the kid and the signature come from one state of the
	// keyring, so a reload never pairs one key's kid with another's signature. It returns
	// ErrNoSigningKey while no key may sign.
	Sign(payload []byte, typ string) (string, error)
}
