package argon2id

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/app"
)

// Options configure a Hasher.
type Options struct {
	Params        Params               // passwords.argon2 memory, iterations and parallelism
	MaxConcurrent int                  // passwords.argon2.max_concurrent: hashing slots, at least 1
	QueueTimeout  time.Duration        // passwords.argon2.queue_timeout: the wait for a slot, above 0
	Peppers       crypto.KeyringSource // the pepper keyring, its other state crypto.StateVerify
}

// Hasher is the Argon2id password hasher (TDD-03 §1). It implements app.PasswordHasher and is
// safe for concurrent use. Formatted or logged, it shows only its parameters.
type Hasher struct {
	params  Params
	peppers crypto.KeyringSource
}

// New returns a Hasher. Parameters outside the bounds a stored hash may have (8 KiB per lane to
// 1 GiB, 1 to 16 iterations, 1 to 16 lanes), no slot, no wait or no keyring are refused.
func New(o Options) (*Hasher, error) {
	if err := o.Params.validate(); err != nil {
		return nil, fmt.Errorf("argon2id: %w", err)
	}
	switch {
	case o.MaxConcurrent < 1:
		return nil, errors.New("argon2id: max concurrent must be at least 1")
	case o.QueueTimeout <= 0:
		return nil, errors.New("argon2id: queue timeout must be above 0")
	case o.Peppers == nil:
		return nil, errors.New("argon2id: no pepper keyring")
	}
	return &Hasher{params: o.Params, peppers: o.Peppers}, nil
}

// Hash implements app.PasswordHasher.
func (h *Hasher) Hash(_ context.Context, password []byte) (string, string, error) {
	id, key := h.peppers.Current().Active()
	v := phc{params: h.params}
	if _, err := rand.Read(v.salt[:]); err != nil {
		return "", "", fmt.Errorf("argon2id: salt: %w", err)
	}
	sum := compute(key, v.params, v.salt[:], password)
	copy(v.hash[:], sum)
	clear(sum)
	return v.encode(), strconv.FormatUint(uint64(id), 10), nil
}

// Verify implements app.PasswordHasher.
func (h *Hasher) Verify(_ context.Context, phcString, pepperKid string, password []byte) (bool, bool, error) {
	kr := h.peppers.Current()
	id, err := parseKid(pepperKid)
	if err != nil {
		return false, false, err
	}
	key, found := kr.Lookup(id)
	if !found {
		return false, false, app.ErrPepperKeyUnknown
	}
	v, err := parsePHC(phcString)
	if err != nil {
		return false, false, err
	}
	sum := compute(key, v.params, v.salt[:], password)
	ok := subtle.ConstantTimeCompare(sum, v.hash[:]) == 1
	clear(sum)
	if !ok {
		return false, false, nil
	}
	active, _ := kr.Active()
	return true, v.params != h.params || id != active, nil
}

// parseKid parses a stored pepper_kid: a key id from 1 to 65535 in canonical decimal.
func parseKid(s string) (uint16, error) {
	n, err := decimal(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, app.ErrPepperKeyUnknown
	}
	return uint16(n), nil
}

// compute returns Argon2id(HMAC-SHA256(key, NFKC(password)), salt, params, 32) (TDD-03 §1.1). The
// temporary copies of the key, the normalised password and the HMAC are cleared.
func compute(key crypto.Key, params Params, salt, password []byte) []byte {
	normal := norm.NFKC.Append(make([]byte, 0, len(password)), password...)
	k := key.Bytes()
	mac := hmac.New(sha256.New, k)
	clear(k)
	mac.Write(normal)
	clear(normal)
	p := mac.Sum(nil)
	defer clear(p)
	return argon2.IDKey(p, salt, params.Iterations, params.MemoryKiB, params.Parallelism, hashSize)
}

// String returns the parameters: "argon2id(m=65536,t=2,p=1)".
func (h Hasher) String() string {
	return fmt.Sprintf("argon2id(m=%d,t=%d,p=%d)", h.params.MemoryKiB, h.params.Iterations, h.params.Parallelism)
}

// GoString is String.
func (h Hasher) GoString() string { return h.String() }

// Format writes String for every verb.
func (h Hasher) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, h.String()) }

// LogValue implements slog.LogValuer: String.
func (h Hasher) LogValue() slog.Value { return slog.StringValue(h.String()) }
