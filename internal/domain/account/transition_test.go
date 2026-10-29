package account

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
)

var (
	testNow     = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	testReasons = []string{"policy_violation", "admin_action"}
	allEffects  = Effects{RevokeSessions: true, CancelFlows: true, EraseCredentials: true, ReleaseIdentifiers: true}
)

// validChange is a request for to that passes validation: a reason for suspended and banned,
// and an until for suspended.
func validChange(to Status) Change {
	c := Change{To: to, AllowedReasons: testReasons}
	if to == StatusSuspended || to == StatusBanned {
		c.ReasonCode = "admin_action"
	}
	if to == StatusSuspended {
		until := testNow.Add(time.Hour)
		c.Until = &until
	}
	return c
}

func ptr[T any](v T) *T { return &v }

// TestT25TransitionTable checks every cell of the SDD §8.1 transition table (0.10), including
// the no-ops and the refusals, and the target pending, which is no column of the table.
func TestT25TransitionTable(t *testing.T) {
	t.Parallel()

	type cell int
	const (
		allowed   cell = iota + 1 // the change is made
		noop                      // 200, nothing written
		refused                   // STATUS_TRANSITION_INVALID
		notTarget                 // VALIDATION_FAILED: account control never sets pending
	)
	type pair struct{ from, to Status }
	table := map[pair]cell{
		{StatusPending, StatusPending}:     notTarget,
		{StatusPending, StatusActive}:      refused,
		{StatusPending, StatusSuspended}:   refused,
		{StatusPending, StatusBanned}:      refused,
		{StatusPending, StatusDeleted}:     allowed,
		{StatusActive, StatusPending}:      notTarget,
		{StatusActive, StatusActive}:       noop,
		{StatusActive, StatusSuspended}:    allowed,
		{StatusActive, StatusBanned}:       allowed,
		{StatusActive, StatusDeleted}:      allowed,
		{StatusSuspended, StatusPending}:   notTarget,
		{StatusSuspended, StatusActive}:    allowed,
		{StatusSuspended, StatusSuspended}: allowed,
		{StatusSuspended, StatusBanned}:    allowed,
		{StatusSuspended, StatusDeleted}:   allowed,
		{StatusBanned, StatusPending}:      notTarget,
		{StatusBanned, StatusActive}:       allowed,
		{StatusBanned, StatusSuspended}:    allowed,
		{StatusBanned, StatusBanned}:       allowed,
		{StatusBanned, StatusDeleted}:      allowed,
		{StatusDeleted, StatusPending}:     notTarget,
		{StatusDeleted, StatusActive}:      refused,
		{StatusDeleted, StatusSuspended}:   refused,
		{StatusDeleted, StatusBanned}:      refused,
		{StatusDeleted, StatusDeleted}:     noop,
	}

	for _, from := range Statuses() {
		for _, to := range Statuses() {
			c, ok := table[pair{from, to}]
			if !ok {
				t.Errorf("no cell for %s → %s", from, to)
				continue
			}
			t.Run(string(from)+"→"+string(to), func(t *testing.T) {
				t.Parallel()
				req := validChange(to)
				got, err := Transition(from, req, testNow)
				switch c {
				case allowed:
					if err != nil {
						t.Fatalf("error = %v, want none", err)
					}
					want := Decision{Changed: true, Status: to, Reason: req.ReasonCode, Until: req.Until}
					if to == StatusDeleted {
						want.Effects = allEffects
					}
					if diff := cmp.Diff(want, got); diff != "" {
						t.Errorf("Decision (-want +got):\n%s", diff)
					}
				case noop:
					if err != nil {
						t.Fatalf("error = %v, want none", err)
					}
					if diff := cmp.Diff(Decision{Status: from}, got); diff != "" {
						t.Errorf("Decision (-want +got):\n%s", diff)
					}
				case refused:
					checkError(t, err, domain.CodeStatusTransitionInvalid, nil)
				case notTarget:
					checkError(t, err, domain.CodeValidationFailed,
						[]domain.FieldError{{Field: "status", Code: FieldNotAllowed}})
				}
			})
		}
	}
}

func TestTransitionValidation(t *testing.T) {
	t.Parallel()

	past := testNow.Add(-time.Second)
	nowElsewhere := testNow.In(time.FixedZone("UTC+1", 3600))
	later := testNow.Add(time.Hour)
	tests := []struct {
		name string
		from Status
		req  Change
		want []domain.FieldError
	}{
		{"suspended without a reason", StatusActive,
			Change{To: StatusSuspended, AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "reason_code", Code: FieldRequired}}},
		{"banned without a reason", StatusActive,
			Change{To: StatusBanned, AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "reason_code", Code: FieldRequired}}},
		{"a reason outside the list", StatusActive,
			Change{To: StatusBanned, ReasonCode: "other", AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "reason_code", Code: FieldUnknown}}},
		{"no reasons configured", StatusActive,
			Change{To: StatusBanned, ReasonCode: "admin_action"},
			[]domain.FieldError{{Field: "reason_code", Code: FieldUnknown}}},
		{"a reason in another case", StatusActive,
			Change{To: StatusBanned, ReasonCode: "Admin_Action", AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "reason_code", Code: FieldUnknown}}},
		{"a reason with white space", StatusActive,
			Change{To: StatusBanned, ReasonCode: " admin_action", AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "reason_code", Code: FieldUnknown}}},
		{"active with a reason", StatusActive,
			Change{To: StatusActive, ReasonCode: "admin_action", AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "reason_code", Code: FieldNotAllowed}}},
		{"active with an until", StatusSuspended,
			Change{To: StatusActive, Until: &later, AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "until", Code: FieldNotAllowed}}},
		{"banned with an until", StatusActive,
			Change{To: StatusBanned, ReasonCode: "admin_action", Until: &later, AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "until", Code: FieldNotAllowed}}},
		{"deleted with a reason", StatusActive,
			Change{To: StatusDeleted, ReasonCode: "admin_action", AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "reason_code", Code: FieldNotAllowed}}},
		{"until in the past", StatusActive,
			Change{To: StatusSuspended, ReasonCode: "admin_action", Until: &past, AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "until", Code: FieldNotFuture}}},
		{"until equal to now in another zone", StatusActive,
			Change{To: StatusSuspended, ReasonCode: "admin_action", Until: &nowElsewhere, AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "until", Code: FieldNotFuture}}},
		{"an unknown status", StatusActive,
			Change{To: "Active", AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "status", Code: FieldUnknown}}},
		{"an unknown status skips the other checks", StatusActive,
			Change{To: "restricted", ReasonCode: "admin_action", Until: &later, AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "status", Code: FieldUnknown}}},
		{"no reason and a past until", StatusActive,
			Change{To: StatusSuspended, Until: &past, AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "reason_code", Code: FieldRequired}, {Field: "until", Code: FieldNotFuture}}},
		{"pending with a reason and an until", StatusActive,
			Change{To: StatusPending, ReasonCode: "admin_action", Until: &later, AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "status", Code: FieldNotAllowed}}},
		{"an invalid body on a refused cell", StatusDeleted,
			Change{To: StatusSuspended, AllowedReasons: testReasons},
			[]domain.FieldError{{Field: "reason_code", Code: FieldRequired}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Transition(tt.from, tt.req, testNow)
			if diff := cmp.Diff(Decision{}, got); diff != "" {
				t.Errorf("Decision on error (-want +got):\n%s", diff)
			}
			checkError(t, err, domain.CodeValidationFailed, tt.want)
		})
	}
}

func TestTransitionUnknownFrom(t *testing.T) {
	t.Parallel()

	for _, from := range []Status{"", "Active", "restricted"} {
		_, err := Transition(from, validChange(StatusActive), testNow)
		checkError(t, err, domain.CodeStatusTransitionInvalid, nil)
	}
}

// TestTransitionSanctionAgain checks that suspending a suspended account, or banning a banned
// one, writes the request's reason and until in place of the stored ones (SDD 0.10).
func TestTransitionSanctionAgain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		from Status
		req  Change
		want Decision
	}{
		{"suspended again without until clears it", StatusSuspended,
			Change{To: StatusSuspended, ReasonCode: "policy_violation", AllowedReasons: testReasons},
			Decision{Changed: true, Status: StatusSuspended, Reason: "policy_violation"}},
		{"suspended again with a new until", StatusSuspended,
			Change{To: StatusSuspended, ReasonCode: "admin_action", Until: ptr(testNow.Add(48 * time.Hour)), AllowedReasons: testReasons},
			Decision{Changed: true, Status: StatusSuspended, Reason: "admin_action", Until: ptr(testNow.Add(48 * time.Hour))}},
		{"banned again with a new reason", StatusBanned,
			Change{To: StatusBanned, ReasonCode: "policy_violation", AllowedReasons: testReasons},
			Decision{Changed: true, Status: StatusBanned, Reason: "policy_violation"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Transition(tt.from, tt.req, testNow)
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Decision (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTransitionCopiesUntil(t *testing.T) {
	t.Parallel()

	until := testNow.Add(time.Hour).In(time.FixedZone("UTC+5", 5*3600))
	req := Change{To: StatusSuspended, ReasonCode: "admin_action", Until: &until, AllowedReasons: testReasons}
	got, err := Transition(StatusActive, req, testNow)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	until = until.Add(time.Hour)
	if got.Until == nil || !got.Until.Equal(testNow.Add(time.Hour)) {
		t.Errorf("Until = %v after the request's value changed, want %v", got.Until, testNow.Add(time.Hour))
	}
	if got.Until != nil && got.Until.Location() != time.UTC {
		t.Errorf("Until location = %v, want UTC", got.Until.Location())
	}
}

// FuzzTransition checks that Transition never panics, fails only with its two codes, and never
// decides a row that the accounts CHECKs of migration 000001 refuse.
func FuzzTransition(f *testing.F) {
	for _, from := range Statuses() {
		for _, to := range Statuses() {
			req := validChange(to)
			f.Add(string(from), string(to), req.ReasonCode, req.Until != nil, int64(3600))
		}
	}
	f.Add("active", "suspended", "", true, int64(-1))
	f.Add("", "", "", false, int64(0))

	f.Fuzz(func(t *testing.T, from, to, reason string, withUntil bool, offsetSeconds int64) {
		req := Change{To: Status(to), ReasonCode: reason, AllowedReasons: testReasons}
		if withUntil {
			req.Until = ptr(testNow.Add(time.Duration(offsetSeconds % (1 << 32) * int64(time.Second))))
		}
		got, err := Transition(Status(from), req, testNow)
		if err != nil {
			var de *domain.Error
			if !errors.As(err, &de) ||
				(de.Code != domain.CodeValidationFailed && de.Code != domain.CodeStatusTransitionInvalid) {
				t.Fatalf("error = %v, want VALIDATION_FAILED or STATUS_TRANSITION_INVALID", err)
			}
			return
		}
		if !got.Changed {
			if got.Effects != (Effects{}) || got.Reason != "" || got.Until != nil {
				t.Fatalf("a no-op decision carries changes: %+v", got)
			}
			return
		}
		if _, err := ParseStatus(string(got.Status)); err != nil {
			t.Fatalf("decided an unknown status %q", got.Status)
		}
		// CHECK (status_until IS NULL OR status = 'suspended')
		if got.Until != nil && got.Status != StatusSuspended {
			t.Fatalf("until with status %s", got.Status)
		}
		// CHECK ((status IN ('suspended','banned')) = (status_reason IS NOT NULL))
		if Restricted(got.Status) != (got.Reason != "") {
			t.Fatalf("status %s with reason %q", got.Status, got.Reason)
		}
		if got.Status == StatusPending {
			t.Fatal("decided pending")
		}
	})
}
