package flow

import (
	"time"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// Challenge is what the verification and resend decisions read of a challenges row: its counters
// and times, never its secret or target.
type Challenge struct {
	Attempts    int
	MaxAttempts int
	Sends       int
	LastSentAt  *time.Time
	ExpiresAt   time.Time
	ClosedAt    *time.Time
	ConsumedAt  *time.Time
}

// End is how a challenge stands (SDD §8.2). The schema stores no close reason for a challenge, so
// End derives it from the row.
type End string

// The challenge ends.
const (
	EndOpen      End = "open"      // open and before expires_at
	EndConsumed  End = "consumed"  // used: consumed_at is set
	EndExhausted End = "exhausted" // unconsumed with attempts at max_attempts
	EndExpired   End = "expired"   // any other closed one, or open at or past expires_at
)

// End returns how c stands at now. An open challenge expires at expires_at itself, as the flow
// lookup's "expires_at > now()" has it (TDD-02 §2.1).
func (c Challenge) End(now time.Time) End {
	switch {
	case c.ConsumedAt != nil:
		return EndConsumed
	case c.Attempts >= c.MaxAttempts:
		return EndExhausted // closed, or about to be: Verify refuses it either way
	case c.ClosedAt != nil || !now.Before(c.ExpiresAt):
		return EndExpired
	default:
		return EndOpen
	}
}

// Outcome is the result of a verification.
type Outcome string

// The verification outcomes.
const (
	Correct   Outcome = "correct"   // consume and close the challenge
	Wrong     Outcome = "wrong"     // store Attempts; answer CODE_INVALID with attempts_left
	Exhausted Outcome = "exhausted" // store Attempts and close the challenge; answer CHALLENGE_CLOSED
	Closed    Outcome = "closed"    // write nothing; answer CHALLENGE_CLOSED
)

// Verification is the decision on one try at a challenge's OTP.
type Verification struct {
	Outcome      Outcome
	Attempts     int // the attempts counter to store; unchanged for Closed
	AttemptsLeft int // for Wrong: tries left, at least 1
}

// Verify decides a try at c's OTP at now. matched is the result of the caller's constant-time
// comparison of the input's MAC with secret_mac (TDD-02 §2.2 step 1).
//
// It mirrors step 2's "UPDATE … SET attempts = attempts + 1 WHERE closed_at IS NULL AND attempts <
// max_attempts": a closed, consumed or expired challenge, or one whose attempts are used up, is
// Closed and its count does not move. Otherwise the try counts before its result (I-4), so on a
// 3-attempt challenge wrong tries 1 and 2 leave 2 and 1, a wrong try 3 is Exhausted, and a right
// try 3 is Correct.
func Verify(c Challenge, matched bool, now time.Time) Verification {
	if c.ClosedAt != nil || c.End(now) != EndOpen || c.Attempts >= c.MaxAttempts {
		return Verification{Outcome: Closed, Attempts: c.Attempts}
	}
	attempts := c.Attempts + 1
	switch {
	case matched:
		return Verification{Outcome: Correct, Attempts: attempts}
	case attempts >= c.MaxAttempts:
		return Verification{Outcome: Exhausted, Attempts: attempts}
	default:
		return Verification{Outcome: Wrong, Attempts: attempts, AttemptsLeft: c.MaxAttempts - attempts}
	}
}

// Err returns the error to answer: nil for Correct, CODE_INVALID with attempts_left for Wrong, and
// CHALLENGE_CLOSED for Exhausted and Closed, which callers cannot tell apart.
func (v Verification) Err() error {
	switch v.Outcome {
	case Correct:
		return nil
	case Wrong:
		left := v.AttemptsLeft
		return &domain.Error{Code: domain.CodeCodeInvalid, Detail: "the code is wrong", AttemptsLeft: &left}
	default:
		return challengeClosed()
	}
}

func challengeClosed() error {
	return &domain.Error{Code: domain.CodeChallengeClosed, Detail: "the challenge is closed"}
}
