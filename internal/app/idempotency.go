package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/arafat-hasan/auth1/internal/domain"
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
	// Claim takes the key for req, as the transaction's first lock: it returns nil when the key
	// was free, or held by a row older than ttl, and is now this transaction's; otherwise it
	// waits for a transaction holding the key and returns the committed row, locked. A wait past
	// its bound is UNAVAILABLE.
	Claim(ctx context.Context, req IdempotencyRequest, ttl time.Duration) (*StoredIdempotency, error)
	// Store records resp for the key Claim took in this transaction, once; anything else is an
	// error.
	Store(ctx context.Context, req IdempotencyRequest, resp IdempotentResponse) error
}

// MaxStoredBody bounds the body of a stored response (TDD-05 §4).
const MaxStoredBody = 64 << 10

// Idempotency runs idempotent operations (TDD-05 §4, I-9). A use case opts in by calling Run
// around its transactional part, with the request the Idempotency-Key middleware built.
type Idempotency struct {
	uow  UnitOfWork
	sp   Savepoints
	keys IdempotencyKeys
	ttl  time.Duration
}

// NewIdempotency returns the component; ttl is retention.idempotency_keys. It refuses a missing
// dependency and a ttl not above 0.
func NewIdempotency(uow UnitOfWork, sp Savepoints, keys IdempotencyKeys, ttl time.Duration) (*Idempotency, error) {
	if uow == nil || sp == nil || keys == nil {
		return nil, errors.New("idempotency: missing a dependency")
	}
	if ttl <= 0 {
		return nil, errors.New("idempotency: the key lifetime must be above 0")
	}
	return &Idempotency{uow: uow, sp: sp, keys: keys, ttl: ttl}, nil
}

// Run runs op once per req's key, in one transaction, and returns the response to send. Call it
// outside any transaction: the key is the transaction's first lock (TDD-01 §4.2), and the
// repository refuses a claim after another lock.
//   - A request without its caller, key or a SHA-256 hash is refused before anything runs.
//   - A key already stored with another hash is IDEMPOTENCY_KEY_REUSED; with the same hash, Run
//     returns the stored response without calling op or render.
//   - Otherwise op runs under a savepoint: an error from op, a refusal, rolls op back to the
//     savepoint, so it leaves no effect. render turns op's error (nil on success) into the
//     response, which must be a 2xx when op succeeded and a 4xx when it refused. Either is stored
//     and committed, with op's effects for a 2xx.
//   - Anything else stores nothing, and Run rolls everything back so the key stays free: a 5xx,
//     a 429, a status that does not match op's result, a body over MaxStoredBody, an error from
//     render, or a savepoint that could not roll back (ErrSavepointRollback). Run returns op's
//     error for a 5xx or 429, else an error naming the fault, joined with render's error if any.
func (i *Idempotency) Run(ctx context.Context, req IdempotencyRequest, op func(ctx context.Context) error,
	render func(err error) (IdempotentResponse, error)) (IdempotentResponse, error) {
	if req.Caller == "" || req.Key == "" || len(req.Hash) != sha256.Size {
		return IdempotentResponse{}, errors.New("idempotency: the request has no caller, key or hash")
	}
	var resp IdempotentResponse
	err := i.uow.Do(ctx, func(ctx context.Context) error {
		stored, err := i.keys.Claim(ctx, req, i.ttl)
		if err != nil {
			return err
		}
		if stored != nil {
			if !bytes.Equal(stored.Hash, req.Hash) {
				return &domain.Error{Code: domain.CodeIdempotencyKeyReused, Detail: "The key was used for a different request."}
			}
			resp = stored.Response
			return nil
		}
		opErr := i.sp.Savepoint(ctx, op)
		if errors.Is(opErr, ErrSavepointRollback) {
			return opErr
		}
		var renderErr error
		resp, renderErr = render(opErr)
		switch {
		case renderErr != nil:
			return fmt.Errorf("idempotency: render the response: %w", renderErr)
		case resp.Status >= 500 || resp.Status == 429:
			if opErr != nil {
				return opErr
			}
			return fmt.Errorf("idempotency: the operation succeeded but rendered status %d", resp.Status)
		case opErr == nil && (resp.Status < 200 || resp.Status > 299):
			return fmt.Errorf("idempotency: the operation succeeded but rendered status %d", resp.Status)
		case opErr != nil && (resp.Status < 400 || resp.Status > 499):
			return fmt.Errorf("idempotency: the operation refused but rendered status %d: %w", resp.Status, opErr)
		case len(resp.Body) > MaxStoredBody:
			return fmt.Errorf("idempotency: a response body of %d bytes is over %d", len(resp.Body), MaxStoredBody)
		}
		return i.keys.Store(ctx, req, resp)
	})
	if err != nil {
		return IdempotentResponse{}, err
	}
	return resp, nil
}
