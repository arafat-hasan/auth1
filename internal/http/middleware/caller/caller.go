package caller

import (
	"context"
	"slices"
)

// Kind is how a caller authenticated.
type Kind string

// The kinds of caller.
const (
	// KindWorkload is a workload identity from the mesh (TDD-05 §1).
	KindWorkload Kind = "workload"
	// KindClient is a client-credentials token's client (TDD-05 §2).
	KindClient Kind = "client"
)

// Caller is the authenticated service a request comes from (TDD-05 §7). Handlers read it with
// From; they never read headers for identity.
type Caller struct {
	Kind Kind
	// ID is the workload identity or the client id, exactly as configured.
	ID string
	// Scopes are those service_auth.callers grants ID, or the token's.
	Scopes []string
	// Actor is the request's Auth1-Actor, verbatim; "" without one. Information only, never an
	// authorisation input (SDD D-13).
	Actor string
}

// Has reports whether the caller holds scope, compared exactly.
func (c Caller) Has(scope string) bool {
	return scope != "" && slices.Contains(c.Scopes, scope)
}

type ctxKey struct{}

// From returns the Caller that the middleware kept in ctx, and false outside a service operation.
func From(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(ctxKey{}).(Caller)
	return c, ok
}

// with returns ctx holding c.
func with(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}
