package account

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// TestTOTPFactorRedactsSecret checks that a TOTP factor never prints its secret, under fmt or
// slog (G-6).
func TestTOTPFactorRedactsSecret(t *testing.T) {
	t.Parallel()
	step := int64(7)
	f := TOTPFactor{Secret: []byte("JBSWY3DPEHPK3PXP"), LastStep: &step}

	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("factor", "f", f, "p", &f)
	for _, out := range []string{
		fmt.Sprint(f), fmt.Sprintf("%v %+v %#v %s", f, f, f, f), fmt.Sprint(&f), logged.String(),
	} {
		// The secret's bytes, as text or as the decimal list %v prints for a []byte.
		if strings.Contains(out, "JBSWY3DP") || strings.Contains(out, "74 66 83") {
			t.Errorf("output %q holds the secret", out)
		}
	}
}
