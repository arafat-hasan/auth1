package app

import "errors"

// Field-encryption failures that callers tell apart with errors.Is. Their texts name no key, no
// plaintext and no row.
var (
	// ErrPlaceInvalid: a Place with an empty table, column or row, a "|" in any of them, or the
	// nil uuid as its row. A programming error, not bad data.
	ErrPlaceInvalid = errors.New("field place invalid")
	// ErrCiphertextInvalid: the ciphertext is malformed, of an unknown format version, or fails
	// authentication (tampered, or moved from another place).
	ErrCiphertextInvalid = errors.New("field ciphertext invalid")
	// ErrUnknownKey: the ciphertext names a key id that the field keyring does not hold.
	ErrUnknownKey = errors.New("field key unknown")
)

// FieldCrypto encrypts personal fields at rest (SDD D-18, TDD-01 §3.1). Repositories call it; the
// domain never sees ciphertext. Seal encrypts under the active key; Open decrypts under the key
// the ciphertext names, active or decrypt-only. The ciphertext is bound to place: opened with
// another place, it fails with ErrCiphertextInvalid.
type FieldCrypto interface {
	Seal(place Place, plaintext []byte) ([]byte, error)
	Open(place Place, ciphertext []byte) ([]byte, error)
}
