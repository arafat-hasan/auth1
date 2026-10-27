package telemetry

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSecretFormatting(t *testing.T) {
	t.Parallel()

	const value = "s3cr3t-value"
	s := Secret(value)
	type holder struct{ S Secret }

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10s"} {
		if got := fmt.Sprintf(verb, s); strings.Contains(got, value) || !strings.Contains(got, Redacted) {
			t.Errorf("Sprintf(%q) = %q", verb, got)
		}
		if got := fmt.Sprintf(verb, holder{s}); strings.Contains(got, value) {
			t.Errorf("Sprintf(%q, struct) = %q", verb, got)
		}
	}
	if got := s.String(); got != Redacted {
		t.Errorf("String() = %q", got)
	}
	if got := s.GoString(); got != Redacted {
		t.Errorf("GoString() = %q", got)
	}
	if got := s.LogValue().String(); got != Redacted {
		t.Errorf("LogValue() = %q", got)
	}
	b, err := json.Marshal(holder{s})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"S":"[REDACTED]"}` {
		t.Errorf("json.Marshal = %s", got)
	}
	if got := s.Reveal(); got != value {
		t.Errorf("Reveal() = %q, want %q", got, value)
	}
}
