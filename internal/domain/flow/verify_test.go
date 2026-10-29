package flow

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
)

var (
	t0      = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	expires = t0.Add(5 * time.Minute)
)

func at(d time.Duration) *time.Time { t := t0.Add(d); return &t }

func open3() Challenge { return Challenge{MaxAttempts: 3, ExpiresAt: expires} }

// TestVerifyAttemptSequence is I-4 on a 3-attempt challenge: wrong tries 1 and 2 answer
// CODE_INVALID with 2 and 1 attempts left, try 3 exhausts it, and the 4th is refused even with the
// right code.
func TestVerifyAttemptSequence(t *testing.T) {
	t.Parallel()

	c := open3()
	want := []Verification{
		{Outcome: Wrong, Attempts: 1, AttemptsLeft: 2},
		{Outcome: Wrong, Attempts: 2, AttemptsLeft: 1},
		{Outcome: Exhausted, Attempts: 3},
	}
	for i, w := range want {
		got := Verify(c, false, t0)
		if diff := cmp.Diff(w, got); diff != "" {
			t.Fatalf("try %d (-want +got):\n%s", i+1, diff)
		}
		c.Attempts = got.Attempts
	}
	c.ClosedAt = at(0) // the caller closes an exhausted challenge
	if got := Verify(c, true, t0); got.Outcome != Closed || got.Attempts != 3 {
		t.Errorf("try 4 with the right code = %+v, want Closed with attempts 3", got)
	}
	// Even if the caller failed to close it, the count alone refuses the 4th try.
	c.ClosedAt = nil
	if got := Verify(c, true, t0); got.Outcome != Closed {
		t.Errorf("try 4 on an unclosed exhausted challenge = %+v, want Closed", got)
	}
}

func TestVerifyCorrect(t *testing.T) {
	t.Parallel()

	for attempts := range 3 {
		c := open3()
		c.Attempts = attempts
		want := Verification{Outcome: Correct, Attempts: attempts + 1}
		if diff := cmp.Diff(want, Verify(c, true, t0)); diff != "" {
			t.Errorf("right code after %d wrong (-want +got):\n%s", attempts, diff)
		}
	}
}

func TestVerifySingleAttempt(t *testing.T) {
	t.Parallel()

	c := Challenge{MaxAttempts: 1, ExpiresAt: expires}
	if got := Verify(c, false, t0); got.Outcome != Exhausted || got.Attempts != 1 {
		t.Errorf("wrong code on a 1-attempt challenge = %+v, want Exhausted", got)
	}
}

// TestVerifyConsumedNeverVerifies is I-4: a consumed challenge never verifies again, whatever its
// attempts and whether or not it was closed.
func TestVerifyConsumedNeverVerifies(t *testing.T) {
	t.Parallel()

	for attempts := range 3 {
		for _, closed := range []bool{true, false} {
			c := open3()
			c.Attempts = attempts
			c.ConsumedAt = at(0)
			if closed {
				c.ClosedAt = at(0)
			}
			want := Verification{Outcome: Closed, Attempts: attempts}
			if diff := cmp.Diff(want, Verify(c, true, t0)); diff != "" {
				t.Errorf("consumed, attempts %d, closed %v (-want +got):\n%s", attempts, closed, diff)
			}
		}
	}
}

// TestVerifyClosedSameAnswer checks that closed, consumed and expired challenges get one answer,
// and that expiry is reached at expires_at itself.
func TestVerifyClosedSameAnswer(t *testing.T) {
	t.Parallel()

	closed := open3()
	closed.ClosedAt = at(0)
	consumed := open3()
	consumed.ClosedAt, consumed.ConsumedAt = at(0), at(0)
	exhausted := open3()
	exhausted.Attempts, exhausted.ClosedAt = 3, at(0)
	expiredClosed := open3()
	expiredClosed.ClosedAt = &expires

	cases := map[string]struct {
		c   Challenge
		now time.Time
	}{
		"closed":                {closed, t0},
		"consumed":              {consumed, t0},
		"exhausted":             {exhausted, t0},
		"expired and closed":    {expiredClosed, expires.Add(time.Minute)},
		"open at expires_at":    {open3(), expires},
		"open after expires_at": {open3(), expires.Add(time.Second)},
	}
	want := &domain.Error{Code: domain.CodeChallengeClosed, Detail: "the challenge is closed"}
	for name, tc := range cases {
		for _, matched := range []bool{true, false} {
			got := Verify(tc.c, matched, tc.now)
			if got.Outcome != Closed || got.Attempts != tc.c.Attempts {
				t.Errorf("%s, matched %v = %+v, want Closed with attempts unchanged", name, matched, got)
			}
			if diff := cmp.Diff(want, got.Err()); diff != "" {
				t.Errorf("%s: Err() (-want +got):\n%s", name, diff)
			}
		}
	}
	justBefore := open3()
	if got := Verify(justBefore, true, expires.Add(-time.Microsecond)); got.Outcome != Correct {
		t.Errorf("a microsecond before expires_at = %+v, want Correct", got)
	}
}

func TestVerificationErr(t *testing.T) {
	t.Parallel()

	two := 2
	tests := []struct {
		v    Verification
		want error
	}{
		{Verification{Outcome: Correct, Attempts: 1}, nil},
		{Verification{Outcome: Wrong, Attempts: 1, AttemptsLeft: 2},
			&domain.Error{Code: domain.CodeCodeInvalid, Detail: "the code is wrong", AttemptsLeft: &two}},
		{Verification{Outcome: Exhausted, Attempts: 3},
			&domain.Error{Code: domain.CodeChallengeClosed, Detail: "the challenge is closed"}},
		{Verification{Outcome: Closed, Attempts: 3},
			&domain.Error{Code: domain.CodeChallengeClosed, Detail: "the challenge is closed"}},
	}
	for _, tt := range tests {
		got := tt.v.Err()
		if tt.want == nil {
			if got != nil {
				t.Errorf("%s: Err() = %v, want nil", tt.v.Outcome, got)
			}
			continue
		}
		if diff := cmp.Diff(tt.want, got); diff != "" {
			t.Errorf("%s: Err() (-want +got):\n%s", tt.v.Outcome, diff)
		}
	}
}

func TestEnd(t *testing.T) {
	t.Parallel()

	consumed := open3()
	consumed.Attempts, consumed.ClosedAt, consumed.ConsumedAt = 3, at(time.Minute), at(time.Minute)
	exhausted := open3()
	exhausted.Attempts, exhausted.ClosedAt = 3, at(time.Minute)
	expired := open3()
	expired.Attempts, expired.ClosedAt = 2, &expires
	closedEarly := open3() // closed with its flow before it expired: not exhausted, not consumed
	closedEarly.ClosedAt = at(time.Minute)

	tests := []struct {
		name string
		c    Challenge
		now  time.Time
		want End
	}{
		{"open", open3(), t0, EndOpen},
		{"open past expires_at", open3(), expires, EndExpired},
		{"consumed", consumed, t0, EndConsumed},
		{"consumed on the last attempt is consumed, not exhausted", consumed, expires.Add(time.Hour), EndConsumed},
		{"exhausted", exhausted, t0, EndExhausted},
		{"expired", expired, expires.Add(time.Minute), EndExpired},
		{"closed early", closedEarly, t0.Add(2 * time.Minute), EndExpired},
	}
	for _, tt := range tests {
		if got := tt.c.End(tt.now); got != tt.want {
			t.Errorf("%s: End = %s, want %s", tt.name, got, tt.want)
		}
	}
}
