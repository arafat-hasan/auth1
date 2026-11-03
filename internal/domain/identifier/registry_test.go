package identifier

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
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
			got := problems(err)
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
	got := problems(err)
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

// problems returns the messages of the PolicyErrors in err, or nil.
func problems(err error) []string {
	var pe PolicyErrors
	if !errors.As(err, &pe) {
		return nil
	}
	var out []string
	for _, e := range pe {
		out = append(out, e.Error())
	}
	return out
}

// noSignIn is a type that cannot sign in.
type noSignIn struct{ Email }

func (noSignIn) Name() string                     { return "nickname" }
func (noSignIn) CanSignIn() bool                  { return false }
func (noSignIn) CheckPolicy(Policy) []PolicyError { return nil }

func TestNormaliseSet(t *testing.T) {
	t.Parallel()
	r, err := NewRegistry(Builtin(), map[string]Policy{
		"email": {Required: true, Verify: flow.MethodEmailLink, SignIn: true},
		"phone": {Verify: flow.MethodSMSOTP, CallingCodes: []string{"44"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const email, phone = "Someone@Example.COM", "+44 7400 123456"
	tests := []struct {
		name   string
		raw    map[string]string
		want   map[string]string
		code   domain.Code
		fields []domain.FieldError
	}{
		{"both", map[string]string{"email": email, "phone": phone},
			map[string]string{"email": "someone@example.com", "phone": "+447400123456"}, "", nil},
		{"required only", map[string]string{"email": email}, map[string]string{"email": "someone@example.com"}, "", nil},
		{"required missing", map[string]string{"phone": phone}, nil, domain.CodeValidationFailed,
			[]domain.FieldError{{Field: "identifiers.email", Code: domain.FieldRequired}}},
		{"empty", map[string]string{}, nil, domain.CodeValidationFailed,
			[]domain.FieldError{{Field: "identifiers.email", Code: domain.FieldRequired}}},
		{"unknown type", map[string]string{"email": email, "username": "someone"}, nil, domain.CodeIdentifierNotAllowed, nil},
		{"bad value", map[string]string{"email": email, "phone": "+1 202 555 0100"}, nil, domain.CodeIdentifierNotAllowed, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := r.NormaliseSet(tt.raw)
			if tt.code == "" {
				if err != nil {
					t.Fatalf("NormaliseSet: %v", err)
				}
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("NormaliseSet (-want +got):\n%s", diff)
				}
				return
			}
			var de *domain.Error
			if !errors.As(err, &de) || de.Code != tt.code {
				t.Fatalf("NormaliseSet: %v; want %s", err, tt.code)
			}
			if diff := cmp.Diff(tt.fields, de.Fields); diff != "" {
				t.Errorf("fields (-want +got):\n%s", diff)
			}
			for _, v := range tt.raw {
				if strings.Contains(err.Error(), v) {
					t.Errorf("error %q holds the value %q", err, v)
				}
			}
		})
	}
}
