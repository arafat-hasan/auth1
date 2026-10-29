package flow

import (
	"time"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// ResendRules are the resend limits of one challenge, from configuration (otp.resend_after,
// otp.cooldown). The per-value send limits of TDD-07 §5 are checked apart.
type ResendRules struct {
	ResendAfter time.Duration // the earliest resend after the last send
	Cooldown    time.Duration // the pause after the attempts are used up
}

// ResendOutcome is the result of a resend request.
type ResendOutcome string

// The resend outcomes (TDD-02 §2.4).
const (
	Reuse        ResendOutcome = "reuse"         // send the open challenge's secret again
	NewChallenge ResendOutcome = "new_challenge" // open a new challenge with a new secret
	TooSoon      ResendOutcome = "too_soon"      // RESEND_TOO_SOON until resend_after has passed
	Cooldown     ResendOutcome = "cooldown"      // RESEND_TOO_SOON until the cooldown ends
	Used         ResendOutcome = "used"          // the challenge was consumed: CHALLENGE_CLOSED
)

// Resend is the decision on a resend request.
type Resend struct {
	Outcome    ResendOutcome
	RetryAfter time.Duration // for TooSoon and Cooldown, in whole seconds, rounded up
}

// DecideResend decides a resend of c at now (TDD-02 §2.4). An open challenge is reused, unless it
// was sent less than ResendAfter ago. An expired one is replaced by a new challenge; the caller
// closes it first if it is still open. An exhausted one is refused until Cooldown has passed since
// it closed, then replaced. A consumed one is refused.
func DecideResend(c Challenge, now time.Time, r ResendRules) Resend {
	switch c.End(now) {
	case EndOpen:
		if c.LastSentAt != nil {
			if wait := c.LastSentAt.Add(r.ResendAfter).Sub(now); wait > 0 {
				return Resend{Outcome: TooSoon, RetryAfter: ceilSecond(wait)}
			}
		}
		return Resend{Outcome: Reuse}
	case EndExhausted:
		if wait := c.ClosedAt.Add(r.Cooldown).Sub(now); wait > 0 {
			return Resend{Outcome: Cooldown, RetryAfter: ceilSecond(wait)}
		}
		return Resend{Outcome: NewChallenge}
	case EndConsumed:
		return Resend{Outcome: Used}
	default:
		return Resend{Outcome: NewChallenge}
	}
}

// ceilSecond rounds d up to a whole second, the unit of Retry-After.
func ceilSecond(d time.Duration) time.Duration {
	return (d + time.Second - 1).Truncate(time.Second)
}

// Err returns the error to answer: nil for Reuse and NewChallenge, RESEND_TOO_SOON with
// RetryAfter for TooSoon and Cooldown, and CHALLENGE_CLOSED for Used.
func (r Resend) Err() error {
	switch r.Outcome {
	case Reuse, NewChallenge:
		return nil
	case Used:
		return challengeClosed()
	default:
		return &domain.Error{Code: domain.CodeResendTooSoon, Detail: "wait before asking for another code", RetryAfter: r.RetryAfter}
	}
}
