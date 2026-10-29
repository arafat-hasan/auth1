package flow

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

var device = uuid.MustParse("01920000-0000-7000-8000-000000000001")

func TestStateRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state State
		json  string
	}{
		{"registration", RegistrationState{PendingTypes: []string{"email", "phone"}},
			`{"pending_types":["email","phone"]}`},
		{"registration done", RegistrationState{PendingTypes: []string{}},
			`{"pending_types":[]}`},
		{"invitation", InvitationState{Roles: []string{"user"}, Accepted: true, PendingTypes: []string{"phone"}},
			`{"roles":["user"],"accepted":true,"pending_types":["phone"]}`},
		{"sign_in", SignInState{FirstFactor: FirstFactorPassword, Step: StepSecondFactor, DeviceID: &device},
			`{"first_factor":"pwd","step":"second_factor","device_id":"01920000-0000-7000-8000-000000000001"}`},
		{"sign_in without device", SignInState{FirstFactor: FirstFactorSMS, Step: StepFirstFactor},
			`{"first_factor":"sms","step":"first_factor"}`},
		{"sign_in email enrolment", SignInState{FirstFactor: FirstFactorEmail, Step: StepEnrolment},
			`{"first_factor":"email","step":"enrolment"}`},
		{"password_reset new", PasswordResetState{},
			`{"started":false}`},
		{"password_reset started", PasswordResetState{Started: true, Proof: ProofTOTP},
			`{"started":true,"proof":"totp"}`},
		{"password_reset sms", PasswordResetState{Started: true, Proof: ProofSMS},
			`{"started":true,"proof":"sms"}`},
		{"password_reset none", PasswordResetState{Started: true, Proof: ProofNone},
			`{"started":true,"proof":"none"}`},
		{"email_change", EmailChangeState{ConfirmOld: ConfirmOldRequired, OldConfirmed: true},
			`{"confirm_old":"required","old_confirmed":true,"new_confirmed":false}`},
		{"email_change both confirmed", EmailChangeState{ConfirmOld: ConfirmOldRequired, OldConfirmed: true, NewConfirmed: true},
			`{"confirm_old":"required","old_confirmed":true,"new_confirmed":true}`},
		{"email_change notify", EmailChangeState{ConfirmOld: ConfirmOldNotify, NewConfirmed: true},
			`{"confirm_old":"notify","old_confirmed":false,"new_confirmed":true}`},
		{"email_change support", EmailChangeState{ConfirmOld: ConfirmOldSupport},
			`{"confirm_old":"support","old_confirmed":false,"new_confirmed":false}`},
		{"phone_change", PhoneChangeState{}, `{}`},
		{"totp_replacement", TOTPReplacementState{}, `{}`},
	}
	seen := map[Kind]bool{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := MarshalState(tt.state)
			if err != nil {
				t.Fatalf("MarshalState: %v", err)
			}
			if string(data) != tt.json {
				t.Errorf("MarshalState = %s, want %s", data, tt.json)
			}
			got, err := UnmarshalState(tt.state.Kind(), data)
			if err != nil {
				t.Fatalf("UnmarshalState: %v", err)
			}
			if diff := cmp.Diff(tt.state, got); diff != "" {
				t.Errorf("round trip (-want +got):\n%s", diff)
			}
		})
		seen[tt.state.Kind()] = true
	}
	for _, k := range Kinds() {
		if !seen[k] {
			t.Errorf("no round-trip case for kind %s", k)
		}
	}
}

func TestMarshalStateNilSlices(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		state State
		want  string
	}{
		{RegistrationState{}, `{"pending_types":[]}`},
		{InvitationState{}, `{"roles":[],"accepted":false,"pending_types":[]}`},
	} {
		data, err := MarshalState(tt.state)
		if err != nil || string(data) != tt.want {
			t.Errorf("MarshalState(%#v) = %s, %v; want %s", tt.state, data, err, tt.want)
		}
	}
}

func TestMarshalStateRefuses(t *testing.T) {
	t.Parallel()

	for _, s := range []State{
		nil,
		RegistrationState{PendingTypes: []string{""}},
		RegistrationState{PendingTypes: []string{"email", "email"}},
		InvitationState{Roles: []string{"user", "user"}},
		InvitationState{Roles: []string{""}},
		SignInState{Step: StepFirstFactor},
		SignInState{FirstFactor: "otp", Step: StepFirstFactor},
		SignInState{FirstFactor: FirstFactorPassword},
		SignInState{FirstFactor: FirstFactorPassword, Step: "done"},
		PasswordResetState{Started: true},
		PasswordResetState{Proof: ProofTOTP},
		PasswordResetState{Started: true, Proof: "email"},
		EmailChangeState{},
		EmailChangeState{ConfirmOld: "optional"},
		EmailChangeState{ConfirmOld: ConfirmOldNotify, OldConfirmed: true},
		EmailChangeState{ConfirmOld: ConfirmOldSupport, OldConfirmed: true},
	} {
		if _, err := MarshalState(s); !errors.Is(err, ErrStateInvalid) {
			t.Errorf("MarshalState(%#v) error = %v, want ErrStateInvalid", s, err)
		}
	}
}

func TestUnmarshalStateRefuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		kind Kind
		json string
	}{
		{"unknown kind", "unknown", `{}`},
		{"not json", KindPhoneChange, `{`},
		{"null", KindPhoneChange, `null`},
		{"array", KindPhoneChange, `[]`},
		{"empty input", KindPhoneChange, ``},
		{"trailing data", KindPhoneChange, `{}{}`},
		{"trailing text", KindRegistration, `{"pending_types":[]} x`},
		{"unknown field on empty kind", KindTOTPReplacement, `{"secret":"x"}`},
		{"unknown field", KindRegistration, `{"pending_types":[],"extra":1}`},
		{"missing pending_types", KindRegistration, `{}`},
		{"null pending_types", KindRegistration, `{"pending_types":null}`},
		{"empty pending type", KindRegistration, `{"pending_types":[""]}`},
		{"duplicate pending type", KindRegistration, `{"pending_types":["email","email"]}`},
		{"pending_types not strings", KindRegistration, `{"pending_types":[1]}`},
		{"missing roles", KindInvitation, `{"accepted":false,"pending_types":[]}`},
		{"missing accepted", KindInvitation, `{"roles":[],"pending_types":[]}`},
		{"null accepted", KindInvitation, `{"roles":[],"accepted":null,"pending_types":[]}`},
		{"duplicate role", KindInvitation, `{"roles":["a","a"],"accepted":false,"pending_types":[]}`},
		{"accepted not bool", KindInvitation, `{"roles":[],"accepted":"yes","pending_types":[]}`},
		{"missing first_factor", KindSignIn, `{"step":"first_factor"}`},
		{"unknown first_factor", KindSignIn, `{"first_factor":"otp","step":"first_factor"}`},
		{"first_factor case", KindSignIn, `{"first_factor":"PWD","step":"first_factor"}`},
		{"missing step", KindSignIn, `{"first_factor":"pwd"}`},
		{"unknown step", KindSignIn, `{"first_factor":"pwd","step":"done"}`},
		{"bad device_id", KindSignIn, `{"first_factor":"pwd","step":"enrolment","device_id":"device"}`},
		{"another kind's shape", KindSignIn, `{"pending_types":[]}`},
		{"missing started", KindPasswordReset, `{}`},
		{"proof before start", KindPasswordReset, `{"started":false,"proof":"totp"}`},
		{"started without proof", KindPasswordReset, `{"started":true}`},
		{"unknown proof", KindPasswordReset, `{"started":true,"proof":"email"}`},
		{"empty proof", KindPasswordReset, `{"started":true,"proof":""}`},
		{"missing confirm_old", KindEmailChange, `{"old_confirmed":false,"new_confirmed":false}`},
		{"unknown confirm_old", KindEmailChange, `{"confirm_old":"optional","old_confirmed":false,"new_confirmed":false}`},
		{"missing new_confirmed", KindEmailChange, `{"confirm_old":"notify","old_confirmed":false}`},
		{"case-folded key", KindRegistration, `{"pending_types":[],"PENDING_TYPES":["email"]}`},
		{"case-folded key alone", KindPasswordReset, `{"Started":true,"proof":"totp"}`},
		{"case-folded optional key", KindSignIn, `{"first_factor":"pwd","step":"enrolment","Device_ID":"01920000-0000-7000-8000-000000000001"}`},
		{"null device_id", KindSignIn, `{"first_factor":"pwd","step":"enrolment","device_id":null}`},
		{"null proof", KindPasswordReset, `{"started":false,"proof":null}`},
		{"old confirmed under notify", KindEmailChange, `{"confirm_old":"notify","old_confirmed":true,"new_confirmed":false}`},
		{"old confirmed under support", KindEmailChange, `{"confirm_old":"support","old_confirmed":true,"new_confirmed":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := UnmarshalState(tt.kind, []byte(tt.json))
			if !errors.Is(err, ErrStateInvalid) {
				t.Errorf("UnmarshalState(%s, %s) = %#v, %v; want ErrStateInvalid", tt.kind, tt.json, got, err)
			}
			if got != nil {
				t.Errorf("UnmarshalState(%s, %s) state = %#v, want nil", tt.kind, tt.json, got)
			}
		})
	}
}

// TestStateHoldsNoSecret fails when a state type gains a field whose name suggests a secret or a
// personal value: state is stored in clear (G-6; the pending TOTP secret is flows.pending_secret).
func TestStateHoldsNoSecret(t *testing.T) {
	t.Parallel()

	types := []State{RegistrationState{}, InvitationState{}, SignInState{}, PasswordResetState{},
		EmailChangeState{}, PhoneChangeState{}, TOTPReplacementState{}}
	if len(types) != len(Kinds()) {
		t.Fatalf("%d state types for %d kinds", len(types), len(Kinds()))
	}
	for _, s := range types {
		rt := reflect.TypeOf(s)
		for i := range rt.NumField() {
			name := strings.ToLower(rt.Field(i).Name + " " + rt.Field(i).Tag.Get("json"))
			for _, word := range []string{"secret", "code", "token", "handle", "password", "value", "target"} {
				if strings.Contains(name, word) {
					t.Errorf("%s.%s: a state field named like a secret or personal value (%q)", rt.Name(), rt.Field(i).Name, word)
				}
			}
		}
	}
}
