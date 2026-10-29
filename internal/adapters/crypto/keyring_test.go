package crypto_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
)

// entry is one keyring entry for keyringYAML.
type entry struct {
	id    int
	first byte // the key is keyBytes(first)
	state string
}

// keyringYAML writes a keyring file's content.
func keyringYAML(entries ...entry) []byte {
	var b bytes.Buffer
	b.WriteString("keys:\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "  - id: %d\n    key: %s\n    state: %s\n", e.id, b64(keyBytes(e.first)), e.state)
	}
	return b.Bytes()
}

func mustKeyring(t *testing.T, entries ...entry) *crypto.Keyring {
	t.Helper()
	k, err := crypto.ParseKeyring(keyringYAML(entries...), crypto.StateDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseKeyring(t *testing.T) {
	t.Parallel()
	k, err := crypto.ParseKeyring(keyringYAML(entry{1, 1, "decrypt"}, entry{2, 50, "active"}), crypto.StateDecrypt)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	id, active := k.Active()
	if id != 2 || !bytes.Equal(active.Bytes(), keyBytes(50)) {
		t.Errorf("Active = %d, want 2 with its key", id)
	}
	old, ok := k.Lookup(1)
	if !ok || !bytes.Equal(old.Bytes(), keyBytes(1)) {
		t.Error("Lookup(1) did not find the decrypt key")
	}
	if _, ok := k.Lookup(3); ok {
		t.Error("Lookup(3) found a key")
	}
	if k.Current() != k {
		t.Error("Current is not the keyring itself")
	}
}

func TestParseKeyringOtherState(t *testing.T) {
	t.Parallel()
	data := keyringYAML(entry{1, 1, "verify"}, entry{2, 50, "active"})
	if _, err := crypto.ParseKeyring(data, "verify"); err != nil {
		t.Errorf("with verify allowed: %v", err)
	}
	if _, err := crypto.ParseKeyring(data, crypto.StateDecrypt); err == nil {
		t.Error("verify accepted where only decrypt is")
	}
	for _, other := range []string{"", crypto.StateActive} {
		if _, err := crypto.ParseKeyring(data, other); err == nil {
			t.Errorf("ParseKeyring accepted %q as the other state", other)
		}
	}
}

func TestParseKeyringRefuses(t *testing.T) {
	t.Parallel()
	good := b64(keyBytes(1))
	for _, tt := range []struct {
		name, data, reason string
	}{
		{"empty file", "", "no keys"},
		{"no keys", "keys: []\n", "no keys"},
		{"not YAML", "keys: [\n", "not valid YAML"},
		{"top-level list", "- id: 1\n  key: " + good + "\n  state: active\n", "not valid YAML"},
		{"unknown field", "keys:\n  - id: 1\n    key: " + good + "\n    state: active\n    kid: 1\n", "line 5"},
		{"zero active", string(keyringYAML(entry{1, 1, "decrypt"})), "no active key"},
		{"two active", string(keyringYAML(entry{1, 1, "active"}, entry{2, 50, "active"})), "several active keys"},
		{"id 0", string(keyringYAML(entry{0, 1, "active"})), "keys[0]: id must be from 1 to 65535"},
		{"id 65536", string(keyringYAML(entry{65536, 1, "active"})), "keys[0]: id must be from 1 to 65535"},
		{"negative id", string(keyringYAML(entry{-1, 1, "active"})), "keys[0]: id must be from 1 to 65535"},
		{"no id", "keys:\n  - key: " + good + "\n    state: active\n", "keys[0]: id must be from 1 to 65535"},
		{"id not a number", "keys:\n  - id: " + good + "\n    key: " + good + "\n    state: active\n", "line 2"},
		{"duplicate id", string(keyringYAML(entry{1, 1, "active"}, entry{1, 50, "decrypt"})), "keys[1]: id 1 is used twice"},
		{"duplicate key", string(keyringYAML(entry{1, 1, "active"}, entry{2, 1, "decrypt"})), "keys[1]: the key of id 1 is used twice"},
		{"bad base64", "keys:\n  - id: 1\n    key: '%%%'\n    state: active\n", "keys[0]: key is not standard base64"},
		{"short key", "keys:\n  - id: 1\n    key: " + b64(keyBytes(1)[:31]) + "\n    state: active\n", "keys[0]: key is not 32 bytes"},
		{"no key", "keys:\n  - id: 1\n    state: active\n", "keys[0]: key is not 32 bytes"},
		{"unknown state", string(keyringYAML(entry{1, 1, "active"}, entry{2, 50, "retired"})), `keys[1]: state must be "active" or "decrypt"`},
		{"no state", "keys:\n  - id: 1\n    key: " + good + "\n", `keys[0]: state must be "active" or "decrypt"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := crypto.ParseKeyring([]byte(tt.data), crypto.StateDecrypt)
			if err == nil {
				t.Fatal("ParseKeyring accepted it")
			}
			if !strings.Contains(err.Error(), tt.reason) {
				t.Errorf("error %q does not contain %q", err, tt.reason)
			}
			for _, first := range []byte{1, 50} {
				if s := b64(keyBytes(first)); strings.Contains(err.Error(), s) {
					t.Errorf("error %q contains a key", err)
				}
			}
		})
	}
}

func TestLoadKeyring(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.yaml")
	if err := os.WriteFile(path, keyringYAML(entry{1, 1, "active"}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.LoadKeyring(path, crypto.StateDecrypt); err != nil {
		t.Errorf("LoadKeyring: %v", err)
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, keyringYAML(entry{1, 1, "decrypt"}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{bad, filepath.Join(dir, "missing.yaml")} {
		if _, err := crypto.LoadKeyring(p, crypto.StateDecrypt); err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("LoadKeyring(%s) = %v, want an error naming the file", p, err)
		}
	}
}

func TestKeyringRedacted(t *testing.T) {
	t.Parallel()
	k := mustKeyring(t, entry{1, 1, "decrypt"}, entry{2, 50, "active"})
	type unexported struct{ k *crypto.Keyring }
	type exported struct{ K *crypto.Keyring }
	for name, v := range map[string]any{
		"pointer":    k,
		"value":      *k,
		"exported":   exported{K: k},
		"unexported": unexported{k: k},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertRedacted(t, v, keyBytes(1), keyBytes(50))
		})
	}
	if got := fmt.Sprint(k); !strings.Contains(got, "active 2") || !strings.Contains(got, "decrypt 1") {
		t.Errorf("Sprint = %q, want the ids and states", got)
	}
}
