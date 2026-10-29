package account

import (
	"fmt"
	"testing"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// TestT7StateFlowMatrix checks every cell of the SDD §8.1 state × flow table: six flows over
// five statuses, sign-in with every combination of its facts.
func TestT7StateFlowMatrix(t *testing.T) {
	t.Parallel()

	signIn := map[Status]func(SignInFacts) SignInOutcome{
		StatusPending: func(f SignInFacts) SignInOutcome {
			if f.IdentifierVerified && f.PasswordCorrect {
				return SignInRegistrationIncomplete
			}
			return SignInInvalidCredentials
		},
		StatusActive: func(f SignInFacts) SignInOutcome {
			if !f.PasswordCorrect {
				return SignInInvalidCredentials
			}
			return SignInFull
		},
		StatusSuspended: restrictedSignIn,
		StatusBanned:    restrictedSignIn,
		StatusDeleted:   func(SignInFacts) SignInOutcome { return SignInInvalidCredentials },
	}
	refresh := map[Status]RefreshOutcome{
		StatusPending:   RefreshNotApplicable,
		StatusActive:    RefreshFull,
		StatusSuspended: RefreshRestricted,
		StatusBanned:    RefreshRestricted,
		StatusDeleted:   RefreshRefused,
	}
	reset := map[Status]PasswordResetOutcome{
		StatusPending:   PasswordResetNothingSent,
		StatusActive:    PasswordResetAllowed,
		StatusSuspended: PasswordResetAllowed,
		StatusBanned:    PasswordResetAllowed,
		StatusDeleted:   PasswordResetNothingSent,
	}
	sensitive := map[Status]SensitiveOutcome{
		StatusPending:   SensitiveNotApplicable,
		StatusActive:    SensitiveAllowed,
		StatusSuspended: SensitiveRestricted,
		StatusBanned:    SensitiveRestricted,
		StatusDeleted:   SensitiveNotApplicable,
	}
	resume := map[Status]ResumeOutcome{
		StatusPending:   ResumeAllowed,
		StatusActive:    ResumeNotApplicable,
		StatusSuspended: ResumeNotApplicable,
		StatusBanned:    ResumeNotApplicable,
		StatusDeleted:   ResumeNotApplicable,
	}
	introspection := map[Status]IntrospectionOutcome{
		StatusPending:   IntrospectionNotApplicable,
		StatusActive:    IntrospectionActive,
		StatusSuspended: IntrospectionActive,
		StatusBanned:    IntrospectionActive,
		StatusDeleted:   IntrospectionInactive,
	}

	for _, s := range Statuses() {
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()

			if want, ok := signIn[s]; !ok {
				t.Error("sign-in: no cell")
			} else {
				for _, f := range allSignInFacts() {
					if got, w := SignIn(s, f), want(f); got != w {
						t.Errorf("SignIn(%s, %+v) = %v, want %v", s, f, got, w)
					}
				}
			}
			checkCell(t, "refresh", s, refresh, Refresh)
			checkCell(t, "password reset", s, reset, PasswordReset)
			checkCell(t, "sensitive operation", s, sensitive, SensitiveOperation)
			checkCell(t, "resume", s, resume, Resume)
			checkCell(t, "introspection", s, introspection, Introspection)
		})
	}
}

// restrictedSignIn is the sign-in cell of suspended and banned.
func restrictedSignIn(f SignInFacts) SignInOutcome {
	switch {
	case !f.PasswordCorrect:
		return SignInInvalidCredentials
	case f.RestrictedSignIn:
		return SignInRestricted
	default:
		return SignInAccountRestricted
	}
}

// allSignInFacts is every combination of SignInFacts.
func allSignInFacts() []SignInFacts {
	var all []SignInFacts
	for i := range 8 {
		all = append(all, SignInFacts{IdentifierVerified: i&1 != 0, PasswordCorrect: i&2 != 0, RestrictedSignIn: i&4 != 0})
	}
	return all
}

// checkCell compares a flow function's outcome for s with the cell of want; a missing cell fails.
func checkCell[O comparable](t *testing.T, flow string, s Status, want map[Status]O, f func(Status) O) {
	t.Helper()
	w, ok := want[s]
	if !ok {
		t.Errorf("%s: no cell", flow)
		return
	}
	if got := f(s); got != w {
		t.Errorf("%s(%s) = %v, want %v", flow, s, got, w)
	}
}

func TestFlowsUnknownStatus(t *testing.T) {
	t.Parallel()

	for _, s := range []Status{"", "Active", "restricted"} {
		for _, f := range allSignInFacts() {
			if got := SignIn(s, f); got != SignInInvalidCredentials {
				t.Errorf("SignIn(%q, %+v) = %v, want %v", s, f, got, SignInInvalidCredentials)
			}
		}
		if got := Refresh(s); got != RefreshRefused {
			t.Errorf("Refresh(%q) = %v", s, got)
		}
		if got := PasswordReset(s); got != PasswordResetNothingSent {
			t.Errorf("PasswordReset(%q) = %v", s, got)
		}
		if got := SensitiveOperation(s); got != SensitiveRestricted {
			t.Errorf("SensitiveOperation(%q) = %v", s, got)
		}
		if got := Resume(s); got != ResumeNotApplicable {
			t.Errorf("Resume(%q) = %v", s, got)
		}
		if got := Introspection(s); got != IntrospectionInactive {
			t.Errorf("Introspection(%q) = %v", s, got)
		}
	}
}

func TestOutcomeErrors(t *testing.T) {
	t.Parallel()

	type outcome interface {
		fmt.Stringer
		Err() error
	}
	tests := []struct {
		o    outcome
		code domain.Code // empty: no error
	}{
		{SignInInvalidCredentials, domain.CodeInvalidCredentials},
		{SignInRegistrationIncomplete, domain.CodeRegistrationIncomplete},
		{SignInAccountRestricted, domain.CodeAccountRestricted},
		{SignInFull, ""},
		{SignInRestricted, ""},
		{RefreshNotApplicable, domain.CodeSessionInvalid},
		{RefreshFull, ""},
		{RefreshRestricted, ""},
		{RefreshRefused, domain.CodeSessionInvalid},
		{SensitiveNotApplicable, domain.CodeAccountRestricted},
		{SensitiveAllowed, ""},
		{SensitiveRestricted, domain.CodeAccountRestricted},
	}
	for _, tt := range tests {
		t.Run(tt.o.String(), func(t *testing.T) {
			t.Parallel()
			err := tt.o.Err()
			if tt.code == "" {
				if err != nil {
					t.Errorf("Err() = %v, want nil", err)
				}
				return
			}
			checkError(t, err, tt.code, nil)
		})
	}
}

func TestOutcomeStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		got  fmt.Stringer
		want string
	}{
		{SignInOutcome(0), "SignInOutcome(0)"},
		{SignInRegistrationIncomplete, "registration_incomplete"},
		{RefreshNotApplicable, "not_applicable"},
		{PasswordResetNothingSent, "nothing_sent"},
		{SensitiveRestricted, "account_restricted"},
		{ResumeAllowed, "allowed"},
		{IntrospectionInactive, "inactive"},
	}
	for _, tt := range tests {
		if s := tt.got.String(); s != tt.want {
			t.Errorf("String() = %q, want %q", s, tt.want)
		}
	}
}
