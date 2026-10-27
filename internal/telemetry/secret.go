package telemetry

import (
	"fmt"
	"io"
	"log/slog"
)

// Secret is a string that is never printed: logging, formatting with any verb and JSON encoding
// all give [REDACTED]. Reveal returns the value. fmt cannot call methods on unexported struct
// fields, so a Secret held in one is printed as it is by %v; keep such structs out of fmt.
type Secret string

// Reveal returns the secret value.
func (s Secret) Reveal() string { return string(s) }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// String implements fmt.Stringer.
func (Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer.
func (Secret) GoString() string { return Redacted }

// Format implements fmt.Formatter for every verb.
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, Redacted) }

// MarshalJSON implements json.Marshaler, so a Secret inside a struct logged with slog.Any is
// redacted too.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }
