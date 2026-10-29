package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
)

// The field ciphertext format (TDD-01 §3.1): version ‖ key id (big-endian) ‖ nonce ‖ ciphertext ‖
// tag.
const (
	formatVersion = 0x01
	headerSize    = 1 + 2
	nonceSize     = 12
	tagSize       = 16
	minCiphertext = headerSize + nonceSize + tagSize
)

// The ways a ciphertext fails to open, apart from an unknown key (app.ErrUnknownKey). Each wraps
// app.ErrCiphertextInvalid.
var (
	ErrCiphertextShort    = fmt.Errorf("%w: too short", app.ErrCiphertextInvalid)
	ErrUnsupportedVersion = fmt.Errorf("%w: unsupported format version", app.ErrCiphertextInvalid)
	ErrAuthentication     = fmt.Errorf("%w: authentication failed", app.ErrCiphertextInvalid)
)

// nilRow is the row of a Place built from the nil uuid, which no record has.
var nilRow = uuid.Nil.String()

// FieldCrypto is the AES-256-GCM field encryption of TDD-01 §3.1, under the keyring its source
// gives at each call. It implements app.FieldCrypto and is safe for concurrent use.
type FieldCrypto struct {
	keys KeyringSource
}

// NewFieldCrypto returns a FieldCrypto that takes its keyring from keys: a *Keyring, or a
// *WatchedKeyring to follow the file.
func NewFieldCrypto(keys KeyringSource) *FieldCrypto {
	return &FieldCrypto{keys: keys}
}

// Seal encrypts plaintext under the active key, with a random nonce, bound to place.
func (f *FieldCrypto) Seal(place app.Place, plaintext []byte) ([]byte, error) {
	ad, err := associatedData(place)
	if err != nil {
		return nil, err
	}
	id, key := f.keys.Current().Active()
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, headerSize+nonceSize, headerSize+nonceSize+len(plaintext)+tagSize)
	out[0] = formatVersion
	binary.BigEndian.PutUint16(out[1:headerSize], id)
	nonce := out[headerSize:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("field encryption nonce: %w", err)
	}
	return aead.Seal(out, nonce, plaintext, ad), nil
}

// Open decrypts a ciphertext sealed for place, under the key it names.
func (f *FieldCrypto) Open(place app.Place, ciphertext []byte) ([]byte, error) {
	ad, err := associatedData(place)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < minCiphertext {
		return nil, ErrCiphertextShort
	}
	if ciphertext[0] != formatVersion {
		return nil, ErrUnsupportedVersion
	}
	key, ok := f.keys.Current().Lookup(binary.BigEndian.Uint16(ciphertext[1:headerSize]))
	if !ok {
		return nil, app.ErrUnknownKey
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[headerSize : headerSize+nonceSize]
	plaintext, err := aead.Open(nil, nonce, ciphertext[headerSize+nonceSize:], ad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// associatedData is "auth1|<table>|<column>|<row>", after checking that place is complete and
// that no part of it contains the separator.
func associatedData(p app.Place) ([]byte, error) {
	for _, part := range []string{p.Table, p.Column, p.Row} {
		if part == "" || strings.Contains(part, "|") {
			return nil, app.ErrPlaceInvalid
		}
	}
	if p.Row == nilRow {
		return nil, app.ErrPlaceInvalid
	}
	return []byte("auth1|" + p.Table + "|" + p.Column + "|" + p.Row), nil
}

// newAEAD returns AES-256-GCM under key.
func newAEAD(key Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key.b()[:])
	if err != nil {
		return nil, fmt.Errorf("field encryption cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("field encryption cipher: %w", err)
	}
	return aead, nil
}
