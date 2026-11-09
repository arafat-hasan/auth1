package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// TestServeIdempotencyKey: serve mounts the Idempotency-Key middleware after the caller check.
// On a stub account-control operation no credentials is 401 before the key is looked at; a
// missing or malformed key is 422; a valid one passes to the stub's 501.
func TestServeIdempotencyKey(t *testing.T) {
	dsn := pgtest.DSN(t)
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile(filepath.Join(root, "config.example.yaml")) //nolint:gosec // the repository's example
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(example), "      scopes: [tokens:introspect]",
		"      scopes: [tokens:introspect, accounts:status:write]", 1)
	if cfg == string(example) {
		t.Fatal("the example's caller scopes line changed; update the test")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil { //nolint:gosec // a test file in a temporary directory
		t.Fatal(err)
	}
	api, _ := startServeConfig(t, path, append(dsnEnv(t, dsn), promoteAtOnce))
	waitReady(t, api, http.StatusOK, "ok", 5*time.Second)

	setStatus := func(identity string, key []string, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut,
			api+"/v1/accounts/0190a0a0-0000-7000-8000-000000000001/status", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if identity != "" {
			req.Header.Set("X-Forwarded-Client-Cert", "URI="+identity)
		}
		for _, k := range key {
			req.Header.Add("Idempotency-Key", k)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	const (
		body     = `{"status":"active"}`
		identity = "spiffe://cluster.local/ns/example/sa/reports"
	)
	// The caller is checked first: no credentials is 401, whatever the key.
	if code, got := setStatus("", nil, body); code != http.StatusUnauthorized || !strings.Contains(got, `"TOKEN_INVALID"`) {
		t.Errorf("no credentials and no key: %d %s, want 401 TOKEN_INVALID", code, got)
	}
	for _, tc := range []struct {
		name string
		key  []string
		body string
		want int
	}{
		{"no key", nil, body, http.StatusUnprocessableEntity},
		{"a space in the key", []string{"a b"}, body, http.StatusUnprocessableEntity},
		{"a duplicate member", []string{"k-1"}, `{"status":"active","status":"active"}`, http.StatusUnprocessableEntity},
		{"valid", []string{"k-1"}, body, http.StatusNotImplemented},
	} {
		code, got := setStatus(identity, tc.key, tc.body)
		if code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, code, got, tc.want)
		}
		if tc.want == http.StatusUnprocessableEntity && !strings.Contains(got, `"VALIDATION_FAILED"`) {
			t.Errorf("%s: %s, want VALIDATION_FAILED", tc.name, got)
		}
	}
}
