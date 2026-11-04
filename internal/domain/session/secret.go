package session

import (
	"fmt"
	"log/slog"
)

// Secret is a refresh token's raw value: a successor as Rotate stores it and Successor returns it
// (TDD-04 §3). It shows "[redacted]" when formatted, logged or encoded; convert it to []byte to
// send or hash it.
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
