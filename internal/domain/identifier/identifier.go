package identifier

import (
	"strings"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
	"github.com/arafat-hasan/auth1/internal/domain/message"
)

// Policy is the configured policy of one identifier type (SDD D-3): whether an account must have
// one, how it is verified, whether it can sign in, and the type's own options.
type Policy struct {
	Required     bool
	Verify       flow.Method
	SignIn       bool
	CallingCodes []string // phone: the allowed country calling codes, without "+"
}

// Type is one identifier type of the registry (TDD-01 §2.1).
type Type interface {
	// Name is the type's name, the value of identifiers.type and the key of its policy.
	Name() string
	// Normalise returns the canonical form of raw under p, or IDENTIFIER_NOT_ALLOWED.
	Normalise(raw string, p Policy) (string, error)
	// VerifyMethods returns the methods that can verify the type, the first being its default.
	VerifyMethods() []flow.Method
	// CanSignIn reports whether the type can be a sign-in identifier; the policy may still turn
	// it off.
	CanSignIn() bool
	// Channel is how a message reaches an identifier of the type (TDD-06 §7).
	Channel() message.Channel
	// Variants returns the forms of a normalised value that a password must not contain
	// (TDD-03 §2).
	Variants(normalised string) []string
	// CheckPolicy returns the problems of p that are specific to the type.
	CheckPolicy(p Policy) []PolicyError
}

// Builtin returns the types 1.0 ships: email and phone.
func Builtin() []Type { return []Type{Email{}, Phone{}} }

// PolicyError is a problem of the identifier policy found at start-up: the type, the policy field
// and what is wrong.
type PolicyError struct {
	Type    string
	Field   string // the policy key, such as "verify"; empty for the type itself
	Message string
}

// Path returns the configuration path of the problem: "identifiers.<type>[.<field>]".
func (e *PolicyError) Path() string {
	if e.Field == "" {
		return "identifiers." + e.Type
	}
	return "identifiers." + e.Type + "." + e.Field
}

// Error returns "<path>: <message>".
func (e *PolicyError) Error() string { return e.Path() + ": " + e.Message }

// PolicyErrors is every problem NewRegistry found, in type order. Match it with errors.As.
type PolicyErrors []PolicyError

// Error returns each problem on a line of its own.
func (e PolicyErrors) Error() string {
	lines := make([]string, len(e))
	for i := range e {
		lines[i] = e[i].Error()
	}
	return strings.Join(lines, "\n")
}

// notAllowed returns the IDENTIFIER_NOT_ALLOWED error with detail, which never holds the value.
func notAllowed(detail string) error {
	return &domain.Error{Code: domain.CodeIdentifierNotAllowed, Detail: detail}
}
