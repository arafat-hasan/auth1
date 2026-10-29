package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/config"
)

const (
	devKey1 = "I1z0jrOxjrLVHlnnRXrok+vmgZZz0yy0N2mqmai/w7M="
	devKey2 = "/8gBF0ADTZwzxBR2sD9dVdknpuRaZjPOaqZNj1iqWII="
)

// badKeys are key files that start-up must refuse, each with the key path and the reason the
// output must give.
var badKeys = []struct {
	name, env, content, path, reason string
}{
	{"two active keys", "AUTH1_ENCRYPTION_KEYRING_FILE",
		"keys:\n  - {id: 1, key: " + devKey1 + ", state: active}\n  - {id: 2, key: " + devKey2 + ", state: active}\n",
		"encryption.keyring_file", "several active keys"},
	{"short MAC key", "AUTH1_ENCRYPTION_MAC_KEY_FILE", "AAAAAAAAAAAAAAAAAAAAAA==\n",
		"encryption.mac_key_file", "not 32 bytes"},
	{"blind-index key not base64", "AUTH1_ENCRYPTION_BLIND_INDEX_KEY_FILE", "not a key\n",
		"encryption.blind_index_key_file", "not standard base64"},
	{"two active pepper keys", "AUTH1_PASSWORDS_PEPPER_KEYRING_FILE",
		"keys:\n  - {id: 1, key: " + devKey1 + ", state: active}\n  - {id: 2, key: " + devKey2 + ", state: active}\n",
		"passwords.pepper_keyring_file", "several active keys"},
	{"pepper key in the field keyring's state", "AUTH1_PASSWORDS_PEPPER_KEYRING_FILE",
		"keys:\n  - {id: 1, key: " + devKey1 + ", state: active}\n  - {id: 2, key: " + devKey2 + ", state: decrypt}\n",
		"passwords.pepper_keyring_file", `state must be "active" or "verify"`},
}

// badKeyEnv writes content to a file and returns the development overrides that point env at it.
func badKeyEnv(t *testing.T, env, content string) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bad")
	writeFile(t, path, content)
	return append(slices.Clone(developmentEnv), env+"="+path)
}

func TestLoadCryptoKeysExample(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	cfg, err := config.Load("config.example.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, problems := loadCryptoKeys(cfg, slog.New(slog.DiscardHandler))
	if len(problems) > 0 {
		t.Fatalf("problems: %v", problems)
	}
	if id, _ := keys.fields.Current().Active(); id != 2 {
		t.Errorf("active field key %d, want 2", id)
	}
	if id, _ := keys.pepper.Current().Active(); id != 1 {
		t.Errorf("active pepper key %d, want 1", id)
	}
	if keys.blindIndex.Bytes() == nil || keys.mac.Bytes() == nil {
		t.Error("a key file was not loaded")
	}
}

func TestConfigCheckRefusesBadKeys(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	for _, tt := range badKeys {
		t.Run(tt.name, func(t *testing.T) {
			env := badKeyEnv(t, tt.env, tt.content)
			cmd := newConfigCmd(func() []string { return env })
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{"check", "--config", "config.example.yaml"})
			err := cmd.Execute()
			if !errors.Is(err, errConfigInvalid) {
				t.Fatalf("config check = %v, want errConfigInvalid\n%s", err, out.String())
			}
			if !strings.Contains(out.String(), "  - "+tt.path+": ") || !strings.Contains(out.String(), tt.reason) {
				t.Errorf("output does not name %s with %q:\n%s", tt.path, tt.reason, out.String())
			}
			for _, k := range []string{devKey1, devKey2} {
				if strings.Contains(out.String(), k) {
					t.Errorf("output shows a key:\n%s", out.String())
				}
			}
		})
	}
}

func TestServeRefusesBadKeys(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	restoreDefaults(t)
	for _, tt := range badKeys {
		t.Run(tt.name, func(t *testing.T) {
			var bound atomic.Bool
			deps := serveDeps{listen: func(string, string) (net.Listener, error) {
				bound.Store(true)
				return nil, errors.New("must not bind")
			}, telemetryTimeout: time.Second}
			var out bytes.Buffer
			err := newTestServeCmd(deps, &out, badKeyEnv(t, tt.env, tt.content), "--config", "config.example.yaml")(context.Background())
			if !errors.Is(err, errConfigInvalid) {
				t.Fatalf("serve = %v, want errConfigInvalid\n%s", err, out.String())
			}
			if !strings.Contains(out.String(), "  - "+tt.path+": ") {
				t.Errorf("output does not name %s:\n%s", tt.path, out.String())
			}
			if bound.Load() {
				t.Error("serve bound a listener with a bad key")
			}
		})
	}
}
