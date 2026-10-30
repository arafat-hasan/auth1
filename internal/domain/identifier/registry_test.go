package identifier

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

func TestNewRegistry(t *testing.T) {
	t.Parallel()
	email := Policy{Required: true, Verify: flow.MethodEmailLink, SignIn: true}
	phone := Policy{Verify: flow.MethodSMSOTP}
	tests := []struct {
		name     string
		policies map[string]Policy
		want     []string // the problems, in order
	}{
		{"default policy", map[string]Policy{"email": email, "phone": phone}, nil},
		{"email only", map[string]Policy{"email": email}, nil},
		{"phone sign-in with codes", map[string]Policy{
			"phone": {Required: true, Verify: flow.MethodSMSOTP, SignIn: true, CallingCodes: []string{"44", "1", "800"}},
		}, nil},
		{"unknown type", map[string]Policy{"email": email, "username": {Verify: flow.MethodEmailCode}}, []string{
			"identifiers.username: unknown identifier type; known: email, phone",
		}},
		{"email verified by SMS", map[string]Policy{"email": {Verify: flow.MethodSMSOTP}}, []string{
			"identifiers.email.verify: must be email_link or email_code",
		}},
		{"email with calling codes", map[string]Policy{"email": {Verify: flow.MethodEmailCode, CallingCodes: []string{"44"}}}, []string{
			"identifiers.email.calling_codes: applies to phone only",
		}},
		{"phone verified by email", map[string]Policy{"phone": {Verify: flow.MethodEmailLink}}, []string{
			"identifiers.phone.verify: must be sms_otp",
		}},
		{"unassigned calling code", map[string]Policy{"phone": {Verify: flow.MethodSMSOTP, CallingCodes: []string{"44", "999", "044"}}}, []string{
			`identifiers.phone.calling_codes[1]: "999" is not an assigned calling code`,
			`identifiers.phone.calling_codes[2]: "044" is not an assigned calling code`,
		}},
		{"required phone with no calling codes", map[string]Policy{"phone": {Required: true, Verify: flow.MethodSMSOTP}}, []string{
			"identifiers.phone.calling_codes: is empty, so no phone is allowed; required or sign_in needs at least one",
		}},
		{"sign-in phone with no calling codes", map[string]Policy{"phone": {SignIn: true, Verify: flow.MethodSMSOTP}}, []string{
			"identifiers.phone.calling_codes: is empty, so no phone is allowed; required or sign_in needs at least one",
		}},
		{"problems sorted by type", map[string]Policy{
			"phone": {Verify: flow.MethodEmailLink},
			"email": {Verify: flow.MethodSMSOTP},
		}, []string{
			"identifiers.email.verify: must be email_link or email_code",
			"identifiers.phone.verify: must be sms_otp",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, err := NewRegistry(Builtin(), tt.policies)
			var got []string
			for _, e := range problems(err) {
				got = append(got, e.Error())
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("problems (-want +got):\n%s", diff)
			}
			if (r == nil) != (err != nil) {
				t.Errorf("registry = %v with error %v", r, err)
			}
		})
	}
}

func TestNewRegistryCannotSignIn(t *testing.T) {
	t.Parallel()
	_, err := NewRegistry([]Type{noSignIn{}}, map[string]Policy{"nickname": {Verify: flow.MethodEmailCode, SignIn: true}})
	var got []string
	for _, e := range problems(err) {
		got = append(got, e.Error())
	}
	want := []string{"identifiers.nickname.sign_in: the nickname type cannot sign in"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("problems (-want +got):\n%s", diff)
	}
}

func TestRegistry(t *testing.T) {
	t.Parallel()
	phone := Policy{Verify: flow.MethodSMSOTP, CallingCodes: []string{"44"}}
	r, err := NewRegistry(Builtin(), map[string]Policy{
		"email": {Required: true, Verify: flow.MethodEmailLink, SignIn: true},
		"phone": phone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"email", "phone"}, r.Types()); diff != "" {
		t.Errorf("Types (-want +got):\n%s", diff)
	}
	if got, err := r.Normalise("email", "Alice@Example.COM"); err != nil || got != "alice@example.com" {
		t.Errorf("Normalise(email) = %q, %v", got, err)
	}
	// The registry applies the type's own policy: 1 is not an allowed calling code.
	if got, err := r.Normalise("phone", "+44 7400 123456"); err != nil || got != "+447400123456" {
		t.Errorf("Normalise(phone) = %q, %v", got, err)
	}
	_, err = r.Normalise("phone", "+1 201-555-0123")
	checkNotAllowed(t, err)
	_, err = r.Normalise("username", "alice")
	checkNotAllowed(t, err)

	if diff := cmp.Diff([]string{"alice@example.com", "alice"}, r.Variants("email", "alice@example.com")); diff != "" {
		t.Errorf("Variants (-want +got):\n%s", diff)
	}
	if got := r.Variants("username", "alice"); got != nil {
		t.Errorf("Variants(username) = %q, want nil", got)
	}
	if p, ok := r.Policy("phone"); !ok || !cmp.Equal(p, phone) {
		t.Errorf("Policy(phone) = %+v, %v", p, ok)
	}
	if _, ok := r.Policy("username"); ok {
		t.Error("Policy(username) found")
	}
	if typ, ok := r.Type("email"); !ok || typ.Name() != "email" {
		t.Errorf("Type(email) = %v, %v", typ, ok)
	}
}

// TestRegistryPolicyIsCopied checks that changing the caller's calling codes after NewRegistry
// does not change the registry.
func TestRegistryPolicyIsCopied(t *testing.T) {
	t.Parallel()
	codes := []string{"44"}
	r, err := NewRegistry(Builtin(), map[string]Policy{"phone": {Verify: flow.MethodSMSOTP, CallingCodes: codes}})
	if err != nil {
		t.Fatal(err)
	}
	codes[0] = "1"
	if _, err := r.Normalise("phone", "+447400123456"); err != nil {
		t.Errorf("Normalise = %v", err)
	}
}

// problems returns the *PolicyError values joined in err.
func problems(err error) []*PolicyError {
	if err == nil {
		return nil
	}
	var out []*PolicyError
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			out = append(out, problems(e)...)
		}
		return out
	}
	var pe *PolicyError
	if errors.As(err, &pe) {
		out = append(out, pe)
	}
	return out
}

// noSignIn is a type that cannot sign in.
type noSignIn struct{ Email }

func (noSignIn) Name() string                     { return "nickname" }
func (noSignIn) CanSignIn() bool                  { return false }
func (noSignIn) CheckPolicy(Policy) []PolicyError { return nil }
