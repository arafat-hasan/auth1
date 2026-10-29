package flow

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// Secret is a freshly drawn OTP, link token or handle (TDD-02 §2.2). It shows "[redacted]" when
// formatted, logged or encoded; convert it to []byte to send, MAC or hash it.
type Secret []byte

const redacted = "[redacted]"

// String returns "[redacted]".
func (Secret) String() string { return redacted }

// GoString returns "[redacted]".
func (Secret) GoString() string { return redacted }

// Format writes "[redacted]" for every verb.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue implements slog.LogValuer: "[redacted]".
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler with "[redacted]", so JSON never carries the value.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MinOTPLength is the shortest OTP auth1 draws (TDD-08 §3.1: otp.length ≥ 6).
const MinOTPLength = 6

// ErrOTPLength reports a NewOTP call with a length below MinOTPLength.
var ErrOTPLength = errors.New("flow: OTP length below 6")

// NewOTP draws a code of length decimal digits from r, which is crypto/rand.Reader outside tests.
// Each digit comes from one byte b < 250 as b % 10; bytes 250…255 are skipped, so every digit is
// equally likely (no modulo bias).
func NewOTP(r io.Reader, length int) (Secret, error) {
	if length < MinOTPLength {
		return nil, ErrOTPLength
	}
	code := make(Secret, 0, length)
	buf := make([]byte, length)
	for len(code) < length {
		n := length - len(code)
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			return nil, fmt.Errorf("flow: read random: %w", err)
		}
		for _, b := range buf[:n] {
			if b < 250 {
				code = append(code, '0'+b%10)
			}
		}
	}
	return code, nil
}

// NewLinkToken draws a link token from r: 32 random bytes, base64url without padding (43
// characters). The caller stores its SHA-256 (TDD-02 §2.2).
func NewLinkToken(r io.Reader) (Secret, error) { return random256(r) }

// NewHandle draws a flow handle from r: 32 random bytes, base64url without padding (43
// characters). The caller stores its SHA-256 (TDD-02 §2.1).
func NewHandle(r io.Reader) (Secret, error) { return random256(r) }

func random256(r io.Reader) (Secret, error) {
	var b [32]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, fmt.Errorf("flow: read random: %w", err)
	}
	s := make(Secret, base64.RawURLEncoding.EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(s, b[:])
	return s, nil
}
