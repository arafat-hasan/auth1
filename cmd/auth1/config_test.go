package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func runConfigCheck(t *testing.T, path string) (string, error) {
	t.Helper()
	cmd := newConfigCmd(func() []string { return nil })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"check", "--config", path})
	err := cmd.Execute()
	return out.String(), err
}

// TestConfigCheckExample runs from the repository root, where the example's relative secret
// paths point at the placeholders in testdata/example.
func TestConfigCheckExample(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))

	out, err := runConfigCheck(t, "config.example.yaml")
	if err != nil {
		t.Fatalf("config check: %v\n%s", err, out)
	}
	if out != "configuration OK\n" {
		t.Errorf("output = %q, want %q", out, "configuration OK\n")
	}
}

func TestConfigCheckBroken(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "broken.yaml")
	broken := "tokens:\n  acess: 1m\n  access_ttl: 1h\ndelivery:\n  adapter: capture\n"
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runConfigCheck(t, path)
	if !errors.Is(err, errConfigInvalid) {
		t.Fatalf("config check error = %v, want errConfigInvalid\n%s", err, out)
	}
	if !strings.HasPrefix(out, "configuration has ") {
		t.Errorf("output does not start with the problem count:\n%s", out)
	}
	for _, path := range []string{"tokens.acess", "tokens.access_ttl", "delivery.adapter", "http.issuer", "clients", "service_auth.mode"} {
		if !strings.Contains(out, "  - "+path+": ") {
			t.Errorf("output does not name %s:\n%s", path, out)
		}
	}
}

// TestConfigCheckIdentifiers checks that a configuration that passes Validate still has its
// identifier policy checked against the identifier-type registry (TDD-01 §2.4). It runs from the
// repository root, like TestConfigCheckExample.
func TestConfigCheckIdentifiers(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))

	example, err := os.ReadFile("config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^identifiers:.*\n(?:  .*\n)+`)
	if !re.Match(example) {
		t.Fatal("config.example.yaml has no identifiers block")
	}
	policy := "identifiers:\n" +
		"  email: { required: true, verify: email_link, sign_in: true, calling_codes: [\"44\"] }\n" +
		"  phone: { required: true, verify: email_code }\n" +
		"  username: { verify: email_code }\n"
	path := filepath.Join(t.TempDir(), "identifiers.yaml")
	if err := os.WriteFile(path, re.ReplaceAll(example, []byte(policy)), 0o600); err != nil { //nolint:gosec // a test file in a temporary directory
		t.Fatal(err)
	}
	out, err := runConfigCheck(t, path)
	if !errors.Is(err, errConfigInvalid) {
		t.Fatalf("config check error = %v, want errConfigInvalid\n%s", err, out)
	}
	want := "configuration has 4 problem(s):\n" +
		"  - identifiers.email.calling_codes: applies to phone only\n" +
		"  - identifiers.phone.verify: must be sms_otp\n" +
		"  - identifiers.phone.calling_codes: is empty, so no phone is allowed; required or sign_in needs at least one\n" +
		"  - identifiers.username: unknown identifier type; known: email, phone\n"
	if !strings.HasPrefix(out, want) {
		t.Errorf("output:\n%s\nwant it to start with:\n%s", out, want)
	}
}

func TestConfigCheckUnreadable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "absent.yaml")
	out, err := runConfigCheck(t, path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("config check error = %v, want one naming %s\n%s", err, path, out)
	}
}

func TestConfigCheckRequiresConfig(t *testing.T) {
	t.Parallel()

	cmd := newConfigCmd(func() []string { return nil })
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"check"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("config check without --config: want an error")
	}
}

// TestConfigCheckInvalidKeyring: config check parses and validates the signing keyring.
func TestConfigCheckInvalidKeyring(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))

	pem, err := filepath.Abs(filepath.Join("testdata", "example", "secrets", "signing", "rs256.pem"))
	if err != nil {
		t.Fatal(err)
	}
	keyring := filepath.Join(t.TempDir(), "keyring.yaml")
	entry := "  - {alg: RS256, state: active, private_key_file: " + pem + "}\n"
	writeFile(t, keyring, "keys:\n"+entry+entry)
	cmd := newConfigCmd(func() []string { return []string{"AUTH1_KEYS_KEYRING_FILE=" + keyring} })
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"check", "--config", "config.example.yaml"})
	if err := cmd.Execute(); !errors.Is(err, errConfigInvalid) {
		t.Fatalf("config check error = %v, want errConfigInvalid\n%s", err, &out)
	}
	if !strings.Contains(out.String(), "  - keys.keyring_file: signing keyring "+keyring+": ") ||
		!strings.Contains(out.String(), "2 active keys") {
		t.Errorf("output does not name the keyring problem:\n%s", &out)
	}
}
