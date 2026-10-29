package flow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// FirstFactor is the first factor a sign-in passed (TDD-02 §2.1). Its value is also the first
// member of the session's amr (TDD-03 §7).
type FirstFactor string

// The first factors.
const (
	FirstFactorPassword FirstFactor = "pwd"
	FirstFactorSMS      FirstFactor = "sms"   // an SMS code
	FirstFactorEmail    FirstFactor = "email" // an email code
)

var firstFactors = []FirstFactor{FirstFactorPassword, FirstFactorSMS, FirstFactorEmail}

// Step is where a sign-in stands (TDD-02 §2.1, TDD-03 §3.4).
type Step string

// The sign-in steps.
const (
	StepFirstFactor  Step = "first_factor"  // an OTP sent, not yet entered (TDD-02 §5.2)
	StepSecondFactor Step = "second_factor" // waiting for the TOTP or a recovery code
	StepEnrolment    Step = "enrolment"     // waiting for TOTP enrolment (TDD-03 §4.1)
)

var steps = []Step{StepFirstFactor, StepSecondFactor, StepEnrolment}

// Proof is what a password reset asks for besides the link (TDD-02 §6).
type Proof string

// The reset proofs.
const (
	ProofTOTP Proof = "totp" // a TOTP code or a recovery code
	ProofSMS  Proof = "sms"  // an SMS code to the verified phone
	ProofNone Proof = "none" // the link alone
)

var proofs = []Proof{ProofTOTP, ProofSMS, ProofNone}

// ConfirmOld is who confirms an email change besides the new address (TDD-02 §7).
type ConfirmOld string

// The email-change confirmation modes.
const (
	ConfirmOldRequired ConfirmOld = "required" // the old address confirms too
	ConfirmOldNotify   ConfirmOld = "notify"   // the old address is told
	ConfirmOldSupport  ConfirmOld = "support"  // a change made by support (TDD-02 §7.2)
)

var confirmOlds = []ConfirmOld{ConfirmOldRequired, ConfirmOldNotify, ConfirmOldSupport}

// State is the non-secret step state of a flow, stored in flows.state (TDD-02 §2.1). There is one
// type per kind; no state holds a secret or a personal value.
type State interface {
	// Kind returns the flow kind the state belongs to.
	Kind() Kind
	validate() error
}

// RegistrationState is the state of a registration flow.
type RegistrationState struct {
	PendingTypes []string `json:"pending_types"` // identifier types not yet verified
}

// InvitationState is the state of an invitation flow.
type InvitationState struct {
	Roles        []string `json:"roles"`         // the roles granted on completion
	Accepted     bool     `json:"accepted"`      // the invitation was accepted (TDD-02 §8)
	PendingTypes []string `json:"pending_types"` // identifier types not yet verified
}

// SignInState is the state of a sign-in flow.
type SignInState struct {
	FirstFactor FirstFactor `json:"first_factor"`
	Step        Step        `json:"step"`
	DeviceID    *uuid.UUID  `json:"device_id,omitempty"` // from the device cookie (TDD-07 §4)
}

// PasswordResetState is the state of a password-reset flow. Proof is set exactly when Started is.
type PasswordResetState struct {
	Started bool  `json:"started"`
	Proof   Proof `json:"proof,omitempty"`
}

// EmailChangeState is the state of an email-change flow.
type EmailChangeState struct {
	ConfirmOld   ConfirmOld `json:"confirm_old"`
	OldConfirmed bool       `json:"old_confirmed"`
	NewConfirmed bool       `json:"new_confirmed"`
}

// PhoneChangeState is the state of a phone-change flow: it has none.
type PhoneChangeState struct{}

// TOTPReplacementState is the state of a TOTP-replacement flow: it has none. The pending secret is
// in flows.pending_secret, encrypted.
type TOTPReplacementState struct{}

// Kind returns KindRegistration.
func (RegistrationState) Kind() Kind { return KindRegistration }

// Kind returns KindInvitation.
func (InvitationState) Kind() Kind { return KindInvitation }

// Kind returns KindSignIn.
func (SignInState) Kind() Kind { return KindSignIn }

// Kind returns KindPasswordReset.
func (PasswordResetState) Kind() Kind { return KindPasswordReset }

// Kind returns KindEmailChange.
func (EmailChangeState) Kind() Kind { return KindEmailChange }

// Kind returns KindPhoneChange.
func (PhoneChangeState) Kind() Kind { return KindPhoneChange }

// Kind returns KindTOTPReplacement.
func (TOTPReplacementState) Kind() Kind { return KindTOTPReplacement }

func (s RegistrationState) validate() error { return distinct("pending_types", s.PendingTypes) }

func (s InvitationState) validate() error {
	if err := distinct("roles", s.Roles); err != nil {
		return err
	}
	return distinct("pending_types", s.PendingTypes)
}

func (s SignInState) validate() error {
	if err := oneOf("first_factor", firstFactors, s.FirstFactor); err != nil {
		return err
	}
	return oneOf("step", steps, s.Step)
}

func (s PasswordResetState) validate() error {
	if !s.Started {
		if s.Proof != "" {
			return errors.New("proof is set before the reset started")
		}
		return nil
	}
	return oneOf("proof", proofs, s.Proof)
}

func (s EmailChangeState) validate() error { return oneOf("confirm_old", confirmOlds, s.ConfirmOld) }

func (PhoneChangeState) validate() error { return nil }

func (TOTPReplacementState) validate() error { return nil }

// distinct refuses an empty or repeated entry in a list field.
func distinct(field string, values []string) error {
	for i, v := range values {
		if v == "" {
			return fmt.Errorf("%s has an empty entry", field)
		}
		if slices.Contains(values[:i], v) {
			return fmt.Errorf("%s has a repeated entry", field)
		}
	}
	return nil
}

// oneOf refuses a value outside the field's enum.
func oneOf[T ~string](field string, values []T, v T) error {
	if !slices.Contains(values, v) {
		return fmt.Errorf("%s is not one of %v", field, values)
	}
	return nil
}

// ErrStateInvalid reports a flow state that does not satisfy its kind's rules, or stored JSON that
// does not decode to one: a fault in the caller or the stored row, never in a request.
var ErrStateInvalid = errors.New("flow: invalid state")

// MarshalState validates s and returns its JSON for flows.state. A nil list is written as [].
func MarshalState(s State) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: nil", ErrStateInvalid)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrStateInvalid, s.Kind(), err)
	}
	switch v := s.(type) {
	case RegistrationState:
		v.PendingTypes = nonNil(v.PendingTypes)
		s = v
	case InvitationState:
		v.Roles = nonNil(v.Roles)
		v.PendingTypes = nonNil(v.PendingTypes)
		s = v
	}
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrStateInvalid, s.Kind(), err)
	}
	return data, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// UnmarshalState decodes flows.state for a flow of kind k. It refuses anything MarshalState would
// not write: unknown fields, a missing or null field that has no omitempty, trailing data, and a
// value outside its field's rules.
func UnmarshalState(k Kind, data []byte) (State, error) {
	var (
		s   State
		err error
	)
	switch k {
	case KindRegistration:
		s, err = decode[RegistrationState](data)
	case KindInvitation:
		s, err = decode[InvitationState](data)
	case KindSignIn:
		s, err = decode[SignInState](data)
	case KindPasswordReset:
		s, err = decode[PasswordResetState](data)
	case KindEmailChange:
		s, err = decode[EmailChangeState](data)
	case KindPhoneChange:
		s, err = decode[PhoneChangeState](data)
	case KindTOTPReplacement:
		s, err = decode[TOTPReplacementState](data)
	default:
		return nil, fmt.Errorf("%w: unknown kind %q", ErrStateInvalid, k)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrStateInvalid, k, err)
	}
	return s, nil
}

// decode decodes data strictly into a T and validates it.
func decode[T State](data []byte) (State, error) {
	if err := requireFields(data, reflect.TypeFor[T]()); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var v T
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the object")
	}
	if err := v.validate(); err != nil {
		return nil, err
	}
	return v, nil
}

// requireFields checks that data is a JSON object holding a non-null value for every field of t
// whose tag has no omitempty.
func requireFields(data []byte, t reflect.Type) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m == nil {
		return errors.New("null, not an object")
	}
	for i := range t.NumField() {
		name, opts, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if opts == "omitempty" {
			continue
		}
		if v, ok := m[name]; !ok || string(v) == "null" {
			return fmt.Errorf("%s is missing", name)
		}
	}
	return nil
}
