package guard

import (
	"slices"
	"testing"

	"github.com/arafat-hasan/auth1/internal/telemetry"
)

func TestCheckMetricNames(t *testing.T) {
	t.Parallel()

	allowed := []string{"auth1_refresh_total"}
	literals := []string{"auth1_refresh_total", "auth1_made_up_total", "AUTH1_HTTP_LISTEN", "auth1", "auth1_made_up_total", "auth1 x"}
	if got, want := CheckMetricNames(literals, allowed), []string{"auth1_made_up_total"}; !slices.Equal(got, want) {
		t.Errorf("CheckMetricNames = %q, want %q", got, want)
	}
}

// notMetrics are the auth1_ names that are not metrics: the PostgreSQL roles of TDD-01 §4.1.
var notMetrics = []string{"auth1_app", "auth1_migrator"}

// TestMetricNames fails when code names an auth1_ metric that TDD-08 §5.2 does not list.
func TestMetricNames(t *testing.T) {
	t.Parallel()

	literals, err := StringLiterals("../..")
	if err != nil {
		t.Fatalf("read literals: %v", err)
	}
	if !slices.Contains(literals, "auth1_refresh_total") {
		t.Fatal("found no catalogue name; is the scan reading the module?")
	}
	for _, name := range CheckMetricNames(literals, append(telemetry.InstrumentNames(), notMetrics...)) {
		t.Errorf("metric %s is not in the TDD-08 §5.2 catalogue", name)
	}
}
