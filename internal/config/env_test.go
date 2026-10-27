package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestEnvOverridesNestedValue(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "tokens:\n  refresh_idle_ttl: 100h\n")
	cfg, err := Load(path, []string{
		"HOME=/root",
		"AUTH1_TOKENS_REFRESH_IDLE_TTL=200h",
		"AUTH1_PASSWORDS_ARGON2_MEMORY=32MiB",
		"AUTH1_RECOVERY_SMS_STEP_UP=true",
		"AUTH1_HTTP_ISSUER=https://id.example.test",
		"AUTH1_OTP_LENGTH=8",
		"AUTH1_DATABASE_DSN_FILE=/run/dsn",
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Default()
	want.Tokens.RefreshIdleTTL = 200 * time.Hour
	want.Passwords.Argon2.Memory = 32 * MiB
	want.Recovery.SMSStepUp = true
	want.HTTP.Issuer = "https://id.example.test"
	want.OTP.Length = 8
	want.Database.DSNFile = NewSecretFile("/run/dsn")
	if diff := cmp.Diff(want, *cfg, cmpConfig...); diff != "" {
		t.Errorf("Load mismatch (-want +got):\n%s", diff)
	}
}

func TestEnvRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		variable string
		wantPath string
	}{
		{name: "no such key", variable: "AUTH1_NOPE=1", wantPath: "AUTH1_NOPE"},
		{name: "a list of sections", variable: "AUTH1_CLIENTS=web", wantPath: "AUTH1_CLIENTS"},
		{name: "a list of strings", variable: "AUTH1_ROLES_CATALOG=user", wantPath: "AUTH1_ROLES_CATALOG"},
		{name: "a map entry", variable: "AUTH1_IDENTIFIERS_EMAIL_VERIFY=email_code", wantPath: "AUTH1_IDENTIFIERS_EMAIL_VERIFY"},
		{name: "a section", variable: "AUTH1_TOKENS=x", wantPath: "AUTH1_TOKENS"},
		{name: "not an integer", variable: "AUTH1_OTP_LENGTH=six", wantPath: "otp.length"},
		{name: "not a boolean", variable: "AUTH1_RECOVERY_SMS_STEP_UP=maybe", wantPath: "recovery.sms_step_up"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(writeConfig(t, ""), []string{tt.variable})
			ps := Problems(err)
			if len(ps) != 1 || ps[0].Path != tt.wantPath {
				t.Fatalf("Problems = %v, want one at %s", ps, tt.wantPath)
			}
			if name, _, _ := strings.Cut(tt.variable, "="); !strings.Contains(ps[0].Error(), name) {
				t.Errorf("problem %q does not name %s", ps[0], name)
			}
		})
	}
}

func TestEnvAmbiguous(t *testing.T) {
	t.Parallel()

	str := reflect.TypeFor[string]()
	_, problems := resolveEnv([]string{"AUTH1_A_B_C=x"}, map[string]reflect.Type{"a.b_c": str, "a_b.c": str})
	if len(problems) != 1 || problems[0].Path != "AUTH1_A_B_C" || !strings.Contains(problems[0].Message, "a.b_c") {
		t.Fatalf("problems = %v, want one ambiguous AUTH1_A_B_C naming both paths", problems)
	}
}

func TestSchemaHasNoAmbiguousEnvNames(t *testing.T) {
	t.Parallel()

	seen := map[string]string{}
	for path := range scalarPaths() {
		name := envName(path)
		if other, ok := seen[name]; ok {
			t.Errorf("%s and %s both map to %s", other, path, name)
		}
		seen[name] = path
	}
}

// TestScalarPathsMatchDefaults checks the schema walk against the defaults: every single value of
// Default() outside a map of sections can be set from the environment, and nothing else can.
func TestScalarPathsMatchDefaults(t *testing.T) {
	t.Parallel()

	want := map[string]bool{}
	for path, v := range flatten(Default()) {
		kind := reflect.TypeOf(v).Kind()
		if kind != reflect.Slice && kind != reflect.Map && !strings.HasPrefix(path, "identifiers.") {
			want[path] = true
		}
	}
	got := map[string]bool{}
	for path := range scalarPaths() {
		got[path] = true
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("scalarPaths mismatch (-want +got):\n%s", diff)
	}
}
