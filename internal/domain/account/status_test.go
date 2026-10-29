package account

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
)

func TestStatuses(t *testing.T) {
	t.Parallel()

	want := []Status{"pending", "active", "suspended", "banned", "deleted"}
	if diff := cmp.Diff(want, Statuses()); diff != "" {
		t.Errorf("Statuses() (-want +got):\n%s", diff)
	}
	constants := []Status{StatusPending, StatusActive, StatusSuspended, StatusBanned, StatusDeleted}
	if diff := cmp.Diff(want, constants); diff != "" {
		t.Errorf("constants (-want +got):\n%s", diff)
	}
}

func TestStatusesReturnsACopy(t *testing.T) {
	t.Parallel()

	Statuses()[0] = "changed"
	if got := Statuses()[0]; got != StatusPending {
		t.Errorf("Statuses()[0] = %q after a caller changed its copy, want %q", got, StatusPending)
	}
}

func TestParseStatus(t *testing.T) {
	t.Parallel()

	for _, s := range Statuses() {
		got, err := ParseStatus(string(s))
		if err != nil || got != s {
			t.Errorf("ParseStatus(%q) = %q, %v; want %q, nil", s, got, err, s)
		}
	}
	for _, in := range []string{"", "Active", " active", "active ", "restricted", "ACTIVE"} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseStatus(in)
			if got != "" {
				t.Errorf("ParseStatus(%q) = %q, want the zero Status", in, got)
			}
			checkError(t, err, domain.CodeValidationFailed,
				[]domain.FieldError{{Field: "status", Code: domain.FieldUnknown}})
		})
	}
}

func TestRestricted(t *testing.T) {
	t.Parallel()

	want := map[Status]bool{
		StatusPending:   false,
		StatusActive:    false,
		StatusSuspended: true,
		StatusBanned:    true,
		StatusDeleted:   false,
	}
	for _, s := range Statuses() {
		w, ok := want[s]
		if !ok {
			t.Errorf("no expectation for %q", s)
			continue
		}
		if got := Restricted(s); got != w {
			t.Errorf("Restricted(%q) = %v, want %v", s, got, w)
		}
	}
	if Restricted("") || Restricted("Suspended") {
		t.Error("Restricted is true for a status that is not suspended or banned")
	}
}
