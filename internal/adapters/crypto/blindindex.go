package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/arafat-hasan/auth1/internal/app"
)

// BlindIndex is the blind index of TDD-01 §3.2: HMAC-SHA256(bidx_key, type ‖ 0x00 ‖ normalised
// value), all 32 bytes. Its key has no id: every index row must use the same key. It implements
// app.BlindIndex and is safe for concurrent use.
type BlindIndex struct {
	key Key
}

// NewBlindIndex returns the blind index under key (encryption.blind_index_key_file). The zero Key
// is refused.
func NewBlindIndex(key Key) (*BlindIndex, error) {
	if key.isZero() {
		return nil, fmt.Errorf("blind index: %w", errKeyZero)
	}
	return &BlindIndex{key: key}, nil
}

// Compute returns the index of normalised under idType. An empty idType, or one containing 0x00,
// is app.ErrBlindIndexType.
func (b *BlindIndex) Compute(idType string, normalised []byte) ([]byte, error) {
	if idType == "" || strings.IndexByte(idType, 0) >= 0 {
		return nil, app.ErrBlindIndexType
	}
	m := hmac.New(sha256.New, b.key.b()[:])
	m.Write([]byte(idType))
	m.Write([]byte{0})
	m.Write(normalised)
	return m.Sum(nil), nil
}
