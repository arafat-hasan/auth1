package identifier

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// Registry is the identifier types the policy configures, each with its policy (TDD-01 §2.1). It
// is built once at start-up and only read after.
type Registry struct {
	types    map[string]Type
	policies map[string]Policy
}

// NewRegistry checks policies against types and returns the registry of the configured types. A
// policy must name a known type, verify it by one of the type's methods, turn sign_in on only for
// a type that can sign in, and pass the type's own checks. Every problem is a *PolicyError,
// joined with errors.Join in type order.
func NewRegistry(types []Type, policies map[string]Policy) (*Registry, error) {
	known := make(map[string]Type, len(types))
	for _, t := range types {
		known[t.Name()] = t
	}
	r := &Registry{types: map[string]Type{}, policies: map[string]Policy{}}
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(policies)) {
		p := policies[name]
		t, ok := known[name]
		if !ok {
			msg := "unknown identifier type; known: " + strings.Join(slices.Sorted(maps.Keys(known)), ", ")
			errs = append(errs, &PolicyError{Type: name, Message: msg})
			continue
		}
		var problems []PolicyError
		if !slices.Contains(t.VerifyMethods(), p.Verify) {
			problems = append(problems, PolicyError{Type: name, Field: "verify", Message: "must be " + orList(t.VerifyMethods())})
		}
		if p.SignIn && !t.CanSignIn() {
			problems = append(problems, PolicyError{Type: name, Field: "sign_in", Message: fmt.Sprintf("the %s type cannot sign in", name)})
		}
		problems = append(problems, t.CheckPolicy(p)...)
		for i := range problems {
			errs = append(errs, &problems[i])
		}
		p.CallingCodes = slices.Clone(p.CallingCodes)
		r.types[name], r.policies[name] = t, p
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return r, nil
}

// Types returns the names of the configured types, sorted.
func (r *Registry) Types() []string { return slices.Sorted(maps.Keys(r.types)) }

// Type returns the configured type named name.
func (r *Registry) Type(name string) (Type, bool) {
	t, ok := r.types[name]
	return t, ok
}

// Policy returns the policy of the configured type named name.
func (r *Registry) Policy(name string) (Policy, bool) {
	p, ok := r.policies[name]
	p.CallingCodes = slices.Clone(p.CallingCodes)
	return p, ok
}

// Normalise returns the canonical form of raw as the type named typ, under its policy. A type the
// policy does not configure is IDENTIFIER_NOT_ALLOWED.
func (r *Registry) Normalise(typ, raw string) (string, error) {
	t, ok := r.types[typ]
	if !ok {
		return "", notAllowed("the identifier type is not allowed")
	}
	return t.Normalise(raw, r.policies[typ])
}

// Variants returns the variants of a normalised value of the type named typ, or nil for a type the
// policy does not configure.
func (r *Registry) Variants(typ, normalised string) []string {
	t, ok := r.types[typ]
	if !ok {
		return nil
	}
	return t.Variants(normalised)
}

// orList returns the methods as "a", "a or b", "a, b or c".
func orList(methods []flow.Method) string {
	s := make([]string, len(methods))
	for i, m := range methods {
		s[i] = string(m)
	}
	if len(s) <= 1 {
		return strings.Join(s, "")
	}
	return strings.Join(s[:len(s)-1], ", ") + " or " + s[len(s)-1]
}
