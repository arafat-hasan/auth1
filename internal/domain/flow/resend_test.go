package flow

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
)

var rules = ResendRules{ResendAfter: 60 * time.Second, Cooldown: 15 * time.Minute}

func TestDecideResend(t *testing.T) {
	t.Parallel()

	now := t0.Add(2 * time.Minute)
	sent := func(ago time.Duration) Challenge {
		c := open3()
		c.Sends = 1
		c.LastSentAt = at(2*time.Minute - ago)
		return c
	}
	exhausted := func(ago time.Duration) Challenge {
		c := open3()
		c.Attempts, c.Sends = 3, 1
		c.ClosedAt = at(2*time.Minute - ago)
		return c
	}
	expired := open3()
	expired.Sends, expired.LastSentAt, expired.ClosedAt = 1, at(0), &expires
	consumed := sent(time.Hour)
	consumed.Attempts, consumed.ClosedAt, consumed.ConsumedAt = 1, at(0), at(0)

	tests := []struct {
		name string
		c    Challenge
		now  time.Time
		want Resend
	}{
		{"never sent", open3(), now, Resend{Outcome: Reuse}},
		{"sent 59 s ago", sent(59 * time.Second), now, Resend{Outcome: TooSoon, RetryAfter: time.Second}},
		{"sent 30.5 s ago", sent(30*time.Second + 500*time.Millisecond), now, Resend{Outcome: TooSoon, RetryAfter: 30 * time.Second}},
		{"sent 60 s ago", sent(60 * time.Second), now, Resend{Outcome: Reuse}},
		{"open past expires_at", sent(time.Hour), expires, Resend{Outcome: NewChallenge}},
		{"expired", expired, expires.Add(time.Minute), Resend{Outcome: NewChallenge}},
		{"exhausted 1 min ago", exhausted(time.Minute), now, Resend{Outcome: Cooldown, RetryAfter: 14 * time.Minute}},
		{"exhausted 14 min 59.9 s ago", exhausted(15*time.Minute - 100*time.Millisecond), now, Resend{Outcome: Cooldown, RetryAfter: time.Second}},
		{"exhausted 15 min ago", exhausted(15 * time.Minute), now, Resend{Outcome: NewChallenge}},
		{"consumed", consumed, now, Resend{Outcome: Used}},
		{"exhausted but not yet closed", Challenge{Attempts: 3, MaxAttempts: 3, ExpiresAt: expires}, now,
			Resend{Outcome: Cooldown, RetryAfter: 15 * time.Minute}},
	}
	for _, tt := range tests {
		if diff := cmp.Diff(tt.want, DecideResend(tt.c, tt.now, rules)); diff != "" {
			t.Errorf("%s (-want +got):\n%s", tt.name, diff)
		}
	}
}

func TestResendErr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		r    Resend
		want error
	}{
		{Resend{Outcome: Reuse}, nil},
		{Resend{Outcome: NewChallenge}, nil},
		{Resend{Outcome: TooSoon, RetryAfter: 5 * time.Second},
			&domain.Error{Code: domain.CodeResendTooSoon, Detail: "wait before asking for another code", RetryAfter: 5 * time.Second}},
		{Resend{Outcome: Cooldown, RetryAfter: 14 * time.Minute},
			&domain.Error{Code: domain.CodeResendTooSoon, Detail: "wait before asking for another code", RetryAfter: 14 * time.Minute}},
		{Resend{Outcome: Used},
			&domain.Error{Code: domain.CodeChallengeClosed, Detail: "the challenge is closed"}},
	}
	for _, tt := range tests {
		got := tt.r.Err()
		if tt.want == nil {
			if got != nil {
				t.Errorf("%s: Err() = %v, want nil", tt.r.Outcome, got)
			}
			continue
		}
		if diff := cmp.Diff(tt.want, got); diff != "" {
			t.Errorf("%s: Err() (-want +got):\n%s", tt.r.Outcome, diff)
		}
	}
}
