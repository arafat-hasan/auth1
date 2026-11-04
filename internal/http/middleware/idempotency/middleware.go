package idempotency

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/middleware/caller"
	"github.com/arafat-hasan/auth1/internal/http/problem"
)

// header is the request header carrying the key.
const header = "Idempotency-Key"

// maxKeyLen is the contract's maxLength for the key.
const maxKeyLen = 255

const (
	keyDetail  = "Idempotency-Key must be one value of 1 to 255 visible ASCII characters."
	bodyDetail = "The request body is not valid JSON."
)

// Options configures the middleware.
type Options struct {
	// Match tells, before dispatch, whether a request is for an operation taking the key
	// (gen.IdempotentRoute).
	Match func(*http.Request) bool
	// Problems renders refusals.
	Problems *problem.Writer
	// Caller returns the request's service caller; nil means caller.From.
	Caller func(context.Context) (caller.Caller, bool)
}

// New returns the Idempotency-Key middleware. Install it after caller.Resolver and below
// middleware.BodyLimit. A request Match refuses passes untouched. For one it matches:
//   - anything but exactly one key of 1 to 255 characters in \x21-\x7E answers 422 VALIDATION_FAILED;
//   - a body over the limit answers 413; a non-empty body that is not I-JSON answers 422;
//   - with no caller (a wiring fault) the answer is 503;
//   - otherwise the handler runs with the body intact and the app.IdempotencyRequest in its
//     context (From).
func New(o Options) func(http.Handler) http.Handler {
	callerOf := o.Caller
	if callerOf == nil {
		callerOf = caller.From
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !o.Match(r) {
				next.ServeHTTP(w, r)
				return
			}
			key, ok := keyOf(r.Header)
			if !ok {
				o.Problems.Write(w, r, &domain.Error{Code: domain.CodeValidationFailed, Detail: keyDetail})
				return
			}
			c, ok := callerOf(r.Context())
			if !ok {
				o.Problems.Write(w, r, errors.New("idempotency: no service caller on an idempotent operation"))
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				o.Problems.Write(w, r, err) // a *http.MaxBytesError renders as 413
				return
			}
			hash, err := RequestHash(r.Method, r.URL.EscapedPath(), body)
			if err != nil {
				o.Problems.Write(w, r, &domain.Error{Code: domain.CodeValidationFailed, Detail: bodyDetail})
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			req := app.IdempotencyRequest{Caller: string(c.Kind) + ":" + c.ID, Key: key, Hash: hash}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, req)))
		})
	}
}

// keyOf returns the request's one valid key, or false.
func keyOf(h http.Header) (string, bool) {
	values := h.Values(header)
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > maxKeyLen {
		return "", false
	}
	for i := range len(values[0]) {
		if b := values[0][i]; b < 0x21 || b > 0x7e {
			return "", false
		}
	}
	return values[0], true
}

type ctxKey struct{}

// From returns the app.IdempotencyRequest the middleware kept in ctx, and false outside an
// operation taking Idempotency-Key.
func From(ctx context.Context) (app.IdempotencyRequest, bool) {
	r, ok := ctx.Value(ctxKey{}).(app.IdempotencyRequest)
	return r, ok
}
