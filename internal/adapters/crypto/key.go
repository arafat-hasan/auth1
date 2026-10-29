package crypto

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// KeySize is the size of every symmetric key: field-encryption, blind-index and MAC keys
// (TDD-08 §4).
const KeySize = 32

// redacted is what a key or keyring shows when formatted or logged.
const redacted = "[redacted]"

var (
	errKeyEncoding = errors.New("key is not standard base64")
	errKeySize     = fmt.Errorf("key is not %d bytes", KeySize)
	errKeyZero     = errors.New("key is the zero Key, not one loaded from a key file")
)

// Key is a 32-byte symmetric key. It never shows its bytes when formatted with fmt or logged with
// slog. The bytes are reached through a function, so fmt shows only an address, under any verb,
// even for a Key in an unexported field of another struct, where its methods cannot be called (a
// pointer would not do: fmt prints what it points to under a verb such as %s). The zero Key holds
// no bytes.
type Key struct {
	b func() *[KeySize]byte
}

// newKey returns a Key holding a copy of b, which must be KeySize bytes.
func newKey(b []byte) Key {
	arr := new([KeySize]byte)
	copy(arr[:], b)
	return Key{b: func() *[KeySize]byte { return arr }}
}

// ParseKey decodes a key file's content: standard base64 (with padding) of exactly 32 bytes,
// surrounding white space ignored. Errors do not quote the input.
func ParseKey(data []byte) (Key, error) {
	text := bytes.TrimSpace(data)
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	defer clear(buf)
	n, err := base64.StdEncoding.Strict().Decode(buf, text)
	if err != nil {
		return Key{}, errKeyEncoding
	}
	if n != KeySize {
		return Key{}, errKeySize
	}
	return newKey(buf[:n]), nil
}

// LoadKeyFile reads and parses a key file (TDD-08 §4). Errors name the file, never its content.
func LoadKeyFile(path string) (Key, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path comes from the configuration
	if err != nil {
		return Key{}, fmt.Errorf("read key file: %w", err)
	}
	defer clear(data)
	k, err := ParseKey(data)
	if err != nil {
		return Key{}, fmt.Errorf("key file %s: %w", path, err)
	}
	return k, nil
}

// Bytes returns a copy of the key. The caller should clear it when done.
func (k Key) Bytes() []byte {
	if k.b == nil {
		return nil
	}
	return bytes.Clone(k.b()[:])
}

// isZero reports whether k is the zero Key, which holds no bytes.
func (k Key) isZero() bool { return k.b == nil }

// equal reports in constant time whether k and o hold the same bytes.
func (k Key) equal(o Key) bool {
	if k.b == nil || o.b == nil {
		return k.b == nil && o.b == nil
	}
	return subtle.ConstantTimeCompare(k.b()[:], o.b()[:]) == 1
}

// String returns "[redacted]".
func (Key) String() string { return redacted }

// GoString returns "[redacted]".
func (Key) GoString() string { return redacted }

// Format writes "[redacted]" for every verb.
func (Key) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue implements slog.LogValuer: "[redacted]".
func (Key) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler with "[redacted]", so encoders (slog's JSON
// handler among them) never see the bytes.
func (Key) MarshalText() ([]byte, error) { return []byte(redacted), nil }
