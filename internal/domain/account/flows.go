package account

import (
	"strconv"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// The functions below are the rows of the SDD §8.1 state × flow table. Each returns a closed
// outcome type whose zero value is no outcome. A "—" cell, a flow that cannot reach an account in
// that status, is the row's NotApplicable outcome; a caller that reaches one refuses. An unknown
// status gets the row's most restrictive outcome.

// SignInFacts are what the sign-in cell of a status needs, besides the status.
type SignInFacts struct {
	IdentifierVerified bool // the identifier signed in with is verified
	PasswordCorrect    bool // the password matches the account's hash
	RestrictedSignIn   bool // statuses.restricted_sign_in
}

// SignInOutcome is what a sign-in with a password gives (SDD §8.1, TDD-02 §5.1).
type SignInOutcome int

// The sign-in outcomes.
const (
	SignInInvalidCredentials     SignInOutcome = iota + 1 // INVALID_CREDENTIALS
	SignInRegistrationIncomplete                          // REGISTRATION_INCOMPLETE: the client offers resume
	SignInAccountRestricted                               // ACCOUNT_RESTRICTED: restricted_sign_in is off
	SignInFull                                            // go on with the required factors (D-8) to a full session
	SignInRestricted                                      // go on with the required factors to a restricted session
)

// SignIn decides a password sign-in to an account in status s. A wrong password is
// INVALID_CREDENTIALS in every status, as TDD-02 §5.1 checks it before the status.
func SignIn(s Status, f SignInFacts) SignInOutcome {
	switch s {
	case StatusPending:
		if f.IdentifierVerified && f.PasswordCorrect {
			return SignInRegistrationIncomplete
		}
	case StatusActive:
		if f.PasswordCorrect {
			return SignInFull
		}
	case StatusSuspended, StatusBanned:
		switch {
		case !f.PasswordCorrect:
		case f.RestrictedSignIn:
			return SignInRestricted
		default:
			return SignInAccountRestricted
		}
	}
	return SignInInvalidCredentials
}

// Err returns the refusal of o as a *domain.Error, or nil when the sign-in goes on.
func (o SignInOutcome) Err() error {
	switch o {
	case SignInFull, SignInRestricted:
		return nil
	case SignInRegistrationIncomplete:
		return &domain.Error{Code: domain.CodeRegistrationIncomplete, Detail: "the registration is not complete"}
	case SignInAccountRestricted:
		return &domain.Error{Code: domain.CodeAccountRestricted, Detail: "the account is restricted"}
	default:
		return &domain.Error{Code: domain.CodeInvalidCredentials, Detail: "the identifier or password is wrong"}
	}
}

func (o SignInOutcome) String() string {
	return name("SignInOutcome", int(o), "invalid_credentials", "registration_incomplete", "account_restricted", "full", "restricted")
}

// RefreshOutcome is what a refresh gives (SDD §8.1, §8.3).
type RefreshOutcome int

// The refresh outcomes.
const (
	RefreshNotApplicable RefreshOutcome = iota + 1 // a pending account has no session
	RefreshFull                                    // full tokens
	RefreshRestricted                              // restricted tokens (D-5)
	RefreshRefused                                 // SESSION_INVALID: the sessions were revoked
)

// Refresh decides a refresh of a session of an account in status s.
func Refresh(s Status) RefreshOutcome {
	switch s {
	case StatusPending:
		return RefreshNotApplicable
	case StatusActive:
		return RefreshFull
	case StatusSuspended, StatusBanned:
		return RefreshRestricted
	default:
		return RefreshRefused
	}
}

// Err returns SESSION_INVALID for a refresh that gives no tokens, or nil.
func (o RefreshOutcome) Err() error {
	if o == RefreshFull || o == RefreshRestricted {
		return nil
	}
	return &domain.Error{Code: domain.CodeSessionInvalid, Detail: "the session is not valid"}
}

func (o RefreshOutcome) String() string {
	return name("RefreshOutcome", int(o), "not_applicable", "full", "restricted", "refused")
}

// PasswordResetOutcome is what asking for a password reset gives (SDD §8.1, D-10). Both answer 202.
type PasswordResetOutcome int

// The password reset outcomes.
const (
	PasswordResetNothingSent PasswordResetOutcome = iota + 1 // no flow opened, nothing sent
	PasswordResetAllowed                                     // the reset of D-10, with its proof; the status is unchanged
)

// PasswordReset decides a password reset for an account in status s.
func PasswordReset(s Status) PasswordResetOutcome {
	switch s {
	case StatusActive, StatusSuspended, StatusBanned:
		return PasswordResetAllowed
	default:
		return PasswordResetNothingSent
	}
}

func (o PasswordResetOutcome) String() string {
	return name("PasswordResetOutcome", int(o), "nothing_sent", "allowed")
}

// SensitiveOutcome is what a sensitive operation (SDD D-9) gives.
type SensitiveOutcome int

// The sensitive operation outcomes.
const (
	SensitiveNotApplicable SensitiveOutcome = iota + 1 // no session reaches it: pending or deleted
	SensitiveAllowed                                   // allowed, with the reauthentication of D-9
	SensitiveRestricted                                // ACCOUNT_RESTRICTED
)

// SensitiveOperation decides a sensitive operation by an account in status s.
func SensitiveOperation(s Status) SensitiveOutcome {
	switch s {
	case StatusPending, StatusDeleted:
		return SensitiveNotApplicable
	case StatusActive:
		return SensitiveAllowed
	default:
		return SensitiveRestricted
	}
}

// Err returns ACCOUNT_RESTRICTED unless the operation is allowed.
func (o SensitiveOutcome) Err() error {
	if o == SensitiveAllowed {
		return nil
	}
	return &domain.Error{Code: domain.CodeAccountRestricted, Detail: "the account is restricted"}
}

func (o SensitiveOutcome) String() string {
	return name("SensitiveOutcome", int(o), "not_applicable", "allowed", "account_restricted")
}

// ResumeOutcome is what resuming a registration or invitation (SDD D-4) gives.
type ResumeOutcome int

// The resume outcomes.
const (
	ResumeNotApplicable ResumeOutcome = iota + 1 // the account has no open registration or invitation
	ResumeAllowed                                // the resume message is sent
)

// Resume decides whether a flow of an account in status s may be resumed.
func Resume(s Status) ResumeOutcome {
	if s == StatusPending {
		return ResumeAllowed
	}
	return ResumeNotApplicable
}

func (o ResumeOutcome) String() string {
	return name("ResumeOutcome", int(o), "not_applicable", "allowed")
}

// IntrospectionOutcome is what introspecting a token of an account gives (SDD §8.1).
type IntrospectionOutcome int

// The introspection outcomes.
const (
	IntrospectionNotApplicable IntrospectionOutcome = iota + 1 // a pending account has no tokens
	IntrospectionActive                                        // active: true, with status as stored
	IntrospectionInactive                                      // active: false
)

// Introspection decides the introspection of a token of an account in status s.
func Introspection(s Status) IntrospectionOutcome {
	switch s {
	case StatusPending:
		return IntrospectionNotApplicable
	case StatusActive, StatusSuspended, StatusBanned:
		return IntrospectionActive
	default:
		return IntrospectionInactive
	}
}

func (o IntrospectionOutcome) String() string {
	return name("IntrospectionOutcome", int(o), "not_applicable", "active", "inactive")
}

// name returns names[v-1], or "typ(v)" for a value outside the type.
func name(typ string, v int, names ...string) string {
	if v < 1 || v > len(names) {
		return typ + "(" + strconv.Itoa(v) + ")"
	}
	return names[v-1]
}
