package app

import (
	"fmt"
	"io"
	"log/slog"
)

// IdempotencyRequest is one request under an Idempotency-Key (TDD-05 §4): the caller the key
// belongs to, the key and the request hash. It prints and logs without the key.
type IdempotencyRequest struct {
	// Caller is "<kind>:<id>" for a service caller, or "system" for auth1's own requests.
	Caller string
	Key    string
	// Hash is sha256(method ‖ 0x00 ‖ path ‖ 0x00 ‖ JCS(body)).
	Hash []byte
}

// String describes the request without its key or hash.
func (r IdempotencyRequest) String() string { return "IdempotencyRequest{[redacted]}" }

// GoString is String.
func (r IdempotencyRequest) GoString() string { return r.String() }

// Format writes String for every verb.
func (r IdempotencyRequest) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }

// LogValue implements slog.LogValuer with String.
func (r IdempotencyRequest) LogValue() slog.Value { return slog.StringValue(r.String()) }
