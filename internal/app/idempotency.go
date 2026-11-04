package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"
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

// IdempotentResponse is the answer an idempotent operation stores and replays (TDD-05 §4): the
// HTTP status, the content type and the body, empty for none. It prints and logs without the
// body, which may hold personal data.
type IdempotentResponse struct {
	Status      int
	ContentType string
	Body        []byte
}

// String describes the response without its body.
func (r IdempotentResponse) String() string {
	return fmt.Sprintf("IdempotentResponse{status: %d, type: %q, body: %d bytes}", r.Status, r.ContentType, len(r.Body))
}

// GoString is String.
func (r IdempotentResponse) GoString() string { return r.String() }

// Format writes String for every verb.
func (r IdempotentResponse) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }

// LogValue implements slog.LogValuer with String.
func (r IdempotentResponse) LogValue() slog.Value { return slog.StringValue(r.String()) }

// StoredIdempotency is a key's committed row: the request hash it was claimed with and the
// response stored for it.
type StoredIdempotency struct {
	Hash     []byte
	Response IdempotentResponse
}

// IdempotencyKeys stores idempotency keys (TDD-05 §4, TDD-01 §4). Both methods run in the
// caller's transaction.
type IdempotencyKeys interface {
	// Claim takes the key for req: it returns nil when the key was free, or held by a row older
	// than ttl, and is now this transaction's; otherwise it waits for a transaction holding the
	// key and returns the committed row, locked. A wait past its bound is UNAVAILABLE.
	Claim(ctx context.Context, req IdempotencyRequest, ttl time.Duration) (*StoredIdempotency, error)
	// Store records resp for the key Claim took.
	Store(ctx context.Context, req IdempotencyRequest, resp IdempotentResponse) error
}
