package app

import (
	"context"
	"errors"
	"time"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// ErrOverloaded is the failure of every PasswordHasher method that could not get a hashing slot
// within passwords.argon2.queue_timeout (SDD D-7, TDD-03 §1.4 step 1): 503 with Retry-After: 1.
var ErrOverloaded = &domain.Error{
	Code: domain.CodeUnavailable, Detail: "The service is busy; try again shortly.", RetryAfter: time.Second,
}

// Password-hash failures that callers tell apart with errors.Is. Neither is a wrong password, and
// their texts name no password, pepper, hash or row.
var (
	// ErrPepperKeyUnknown: the stored pepper key id is not one the pepper keyring holds.
	ErrPepperKeyUnknown = errors.New("pepper key unknown")
	// ErrPasswordHashInvalid: the stored PHC string is malformed or its parameters are out of
	// bounds.
	ErrPasswordHashInvalid = errors.New("password hash invalid")
)

// PasswordHasher hashes and verifies passwords (SDD D-7, TDD-03 §1): Argon2id over an HMAC of the
// NFKC-normalised password under a pepper key. Every method waits for one of a bounded number of
// hashing slots, and returns ErrOverloaded after passwords.argon2.queue_timeout, or ctx's error if
// ctx ends first. Callers never call it inside a transaction (G-4). The password is not retained.
type PasswordHasher interface {
	// Hash returns the PHC string of password, under the active pepper key, and that key's id as
	// plain decimal text (for example "3"), stored as password_credentials.pepper_kid.
	Hash(ctx context.Context, password []byte) (phc, pepperKid string, err error)
	// Verify reports whether password matches phc, recomputed with phc's own parameters and the
	// pepper key pepperKid, active or verify-only. needsRehash is true when ok and the parameters
	// differ from the configured ones or pepperKid is not the active key (TDD-03 §1.4 step 3).
	// It returns ErrPepperKeyUnknown or ErrPasswordHashInvalid for a stored value it cannot use.
	Verify(ctx context.Context, phc, pepperKid string, password []byte) (ok, needsRehash bool, err error)
	// VerifyDummy does the work of Verify against a dummy hash, for an identifier that matches no
	// account, so that the time does not tell (TDD-03 §1.4 step 4). ok is always false.
	VerifyDummy(ctx context.Context, password []byte) (ok bool, err error)
}
