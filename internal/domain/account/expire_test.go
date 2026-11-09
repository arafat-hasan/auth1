package account

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestExpire checks the expiry decision for every status: only a pending account is deleted, with
// its identifiers released and nothing else (TDD-02 §2.5, I-12).
func TestExpire(t *testing.T) {
	t.Parallel()
	for _, s := range Statuses() {
		d, ok := Expire(s)
		if s != StatusPending {
			if ok || d != (Decision{}) {
				t.Errorf("Expire(%s) = %+v, %v; want nothing", s, d, ok)
			}
			continue
		}
		want := Decision{Changed: true, Status: StatusDeleted, Effects: Effects{ReleaseIdentifiers: true}}
		if !ok {
			t.Fatalf("Expire(pending) not ok")
		}
		if diff := cmp.Diff(want, d); diff != "" {
			t.Errorf("Expire(pending) (-want +got):\n%s", diff)
		}
	}
}
