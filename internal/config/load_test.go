package config

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var cmpConfig = []cmp.Option{cmp.AllowUnexported(SecretFile{}), cmpopts.EquateEmpty()}

// writeConfig writes a YAML configuration to a temporary file and returns its path.
func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, yaml, 0o600)
	return path
}

// mustLoad loads yaml with no environment and fails the test on any error.
func mustLoad(t *testing.T, yaml string) *Config {
	t.Helper()
	cfg, err := Load(writeConfig(t, yaml), nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestLoadFileOverridesDefaults(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, "tokens:\n  access_ttl: 10m\n")
	want := Default()
	want.Tokens.AccessTTL = 10 * time.Minute
	if diff := cmp.Diff(want, *cfg, cmpConfig...); diff != "" {
		t.Errorf("Load mismatch (-want +got):\n%s", diff)
	}
}

func TestLoadEmptyFileGivesDefaults(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, "")
	if diff := cmp.Diff(Default(), *cfg, cmpConfig...); diff != "" {
		t.Errorf("Load mismatch (-want +got):\n%s", diff)
	}
}

func TestLoadListsAndMapsReplaceDefaults(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, `
roles:
  catalog: [ops]
identifiers:
  email: { required: true, verify: email_code, sign_in: true }
`)
	if diff := cmp.Diff([]string{"ops"}, cfg.Roles.Catalog); diff != "" {
		t.Errorf("roles.catalog (-want +got):\n%s", diff)
	}
	want := map[string]IdentifierPolicy{"email": {Required: true, Verify: VerifyEmailCode, SignIn: true}}
	if diff := cmp.Diff(want, cfg.Identifiers, cmpConfig...); diff != "" {
		t.Errorf("identifiers (-want +got):\n%s", diff)
	}
}

// TestLoadMapEntryKeepsDefaults: an entry the file names gets that entry's defaults under the
// values it sets; a default entry the file does not name is dropped.
func TestLoadMapEntryKeepsDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want map[string]IdentifierPolicy
	}{
		{name: "one field set", yaml: "identifiers:\n  email: { verify: email_code }\n",
			want: map[string]IdentifierPolicy{"email": {Required: true, Verify: VerifyEmailCode, SignIn: true}}},
		{name: "entry without a value", yaml: "identifiers:\n  email:\n",
			want: map[string]IdentifierPolicy{"email": Default().Identifiers["email"]}},
		{name: "map without a value", yaml: "identifiers:\n", want: Default().Identifiers},
		{name: "new entry", yaml: "identifiers:\n  username: { verify: email_link }\n",
			want: map[string]IdentifierPolicy{"username": {Verify: VerifyEmailLink}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := mustLoad(t, tt.yaml)
			if diff := cmp.Diff(tt.want, cfg.Identifiers, cmpConfig...); diff != "" {
				t.Errorf("identifiers (-want +got):\n%s", diff)
			}
		})
	}
}

// TestLoadKeyWithoutValueKeepsDefaults: a section or key left empty, for example with its lines
// commented out, keeps its defaults rather than becoming zero.
func TestLoadKeyWithoutValueKeepsDefaults(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, "tokens:\nrate_limits:\n  global_ip:\npasswords:\n  min_length:\n")
	if diff := cmp.Diff(Default(), *cfg, cmpConfig...); diff != "" {
		t.Errorf("Load mismatch (-want +got):\n%s", diff)
	}
}

// TestLoadReportsEveryProblem: a decoding error does not hide unknown keys or refused variables.
func TestLoadReportsEveryProblem(t *testing.T) {
	t.Parallel()

	cfg, err := Load(writeConfig(t, "tokens:\n  acess_ttl: 1m\n  access_ttl: 900\n"), []string{"AUTH1_NOPE=1"})
	if cfg != nil {
		t.Error("Load returned a configuration with a decoding error")
	}
	var paths []string
	for _, p := range Problems(err) {
		paths = append(paths, p.Path)
	}
	want := []string{"AUTH1_NOPE", "tokens.access_ttl", "tokens.acess_ttl"}
	if diff := cmp.Diff(want, paths); diff != "" {
		t.Errorf("problem paths (-want +got):\n%s", diff)
	}
}

func TestLoadUnknownKeys(t *testing.T) {
	t.Parallel()

	cfg, err := Load(writeConfig(t, `
tokens:
  acess_ttl: 10m
clients:
  - id: web
    colour: blue
identifiers:
  email: { verfy: email_link }
nope: 1
`), nil)
	if err == nil {
		t.Fatal("Load: want an error")
	}
	if cfg == nil {
		t.Fatal("Load returned no configuration with unknown-key problems")
	}
	var paths []string
	for _, p := range Problems(err) {
		paths = append(paths, p.Path)
	}
	want := []string{"clients[0].colour", "identifiers.email.verfy", "nope", "tokens.acess_ttl"}
	if diff := cmp.Diff(want, paths); diff != "" {
		t.Errorf("problem paths (-want +got):\n%s", diff)
	}
}

func TestLoadByteSizes(t *testing.T) {
	t.Parallel()

	for yaml, want := range map[string]ByteSize{"64MiB": 64 * MiB, "1048576": MiB} {
		cfg := mustLoad(t, "passwords:\n  argon2:\n    memory: "+yaml+"\n")
		if cfg.Passwords.Argon2.Memory != want {
			t.Errorf("memory %s = %d, want %d", yaml, cfg.Passwords.Argon2.Memory, want)
		}
	}
}

func TestLoadSecretFile(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, "database:\n  dsn_file: /run/dsn\n")
	if got := cfg.Database.DSNFile.Path(); got != "/run/dsn" {
		t.Errorf("database.dsn_file = %q, want /run/dsn", got)
	}
}

func TestLoadClientDefaults(t *testing.T) {
	t.Parallel()

	cfg := mustLoad(t, "clients:\n  - id: web\n  - id: console\n    mfa: required\n")
	if got := cfg.Clients[0].MFA; got != MFAOptional {
		t.Errorf("clients[0].mfa = %q, want %q", got, MFAOptional)
	}
	if got := cfg.Clients[1].MFA; got != MFARequired {
		t.Errorf("clients[1].mfa = %q, want %q", got, MFARequired)
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want []string // substrings of the error
	}{
		{name: "bare integer duration", yaml: "tokens:\n  access_ttl: 900\n", want: []string{"tokens.access_ttl", "Go duration syntax"}},
		{name: "bad duration", yaml: "tokens:\n  access_ttl: soon\n", want: []string{"tokens.access_ttl"}},
		{name: "bad byte size", yaml: "passwords:\n  argon2:\n    memory: 64mb\n", want: []string{"passwords.argon2.memory"}},
		{name: "negative byte size", yaml: "passwords:\n  argon2:\n    memory: -1\n", want: []string{"passwords.argon2.memory"}},
		{name: "string for an integer", yaml: "otp:\n  length: six\n", want: []string{"otp.length"}},
		{name: "invalid YAML", yaml: "tokens: [\n", want: []string{"config.yaml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Load(writeConfig(t, tt.yaml), nil)
			if err == nil {
				t.Fatalf("Load: want an error, got %+v", cfg.Tokens)
			}
			if cfg != nil {
				t.Error("Load returned a configuration with a decoding error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
			if strings.Contains(tt.want[0], ".") && !strings.HasSuffix(tt.want[0], ".yaml") {
				if ps := Problems(err); len(ps) != 1 || ps[0].Path != tt.want[0] {
					t.Errorf("Problems = %v, want one at %s", ps, tt.want[0])
				}
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "absent.yaml")
	_, err := Load(path, nil)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("Load(%s) error = %v, want one naming the path", path, err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error %v does not wrap fs.ErrNotExist", err)
	}
}
