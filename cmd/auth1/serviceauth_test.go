package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/http/middleware/caller"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

func TestLoadServiceAuth(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.HTTP.BasePath = "/auth"
	cfg.ServiceAuth.Mode = config.ServiceAuthBoth
	cfg.ServiceAuth.Mesh = config.Mesh{
		Source: config.MeshSourceHeader, Header: "l5d-client-id", Format: config.MeshFormatPlain,
		TrustedSidecarCIDRs: []string{"10.0.0.0/8"},
	}
	cfg.ServiceAuth.Callers = []config.Caller{
		{Identity: "spiffe://a", Scopes: []string{"tokens:introspect"}},
		{Identity: "spiffe://b"},
	}
	got, problems := loadServiceAuth(&cfg)
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	want := caller.Options{
		Mode: caller.ModeBoth, Source: caller.SourceHeader, Header: "l5d-client-id", Format: caller.FormatPlain,
		TrustedSidecars: []string{"10.0.0.0/8"}, BasePath: "/auth",
		Callers: map[string][]string{"spiffe://a": {"tokens:introspect"}, "spiffe://b": nil},
	}
	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(caller.Options{}, "Match")); diff != "" {
		t.Errorf("options (-want +got):\n%s", diff)
	}
	for mode, want := range map[config.ServiceAuthMode]caller.Mode{
		"": caller.ModeNone, config.ServiceAuthMesh: caller.ModeMesh, config.ServiceAuthClientCredentials: caller.ModeClientCredentials,
	} {
		cfg.ServiceAuth.Mode = mode
		if got, _ := loadServiceAuth(&cfg); got.Mode != want {
			t.Errorf("mode %q: %v, want %v", mode, got.Mode, want)
		}
	}
	cfg.ServiceAuth.Mesh.Source = config.MeshSourcePeerCert
	if got, _ := loadServiceAuth(&cfg); got.Source != caller.SourcePeerCert {
		t.Errorf("peer_cert: source %v", got.Source)
	}
}

func TestLoadServiceAuthBadSidecarCIDR(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.ServiceAuth.Mesh.TrustedSidecarCIDRs = []string{"127.0.0.1/32", "127.0.0.1", "sidecar"}
	_, problems := loadServiceAuth(&cfg)
	var paths []string
	for _, p := range problems {
		paths = append(paths, p.Path)
	}
	want := []string{"service_auth.mesh.trusted_sidecar_cidrs[1]", "service_auth.mesh.trusted_sidecar_cidrs[2]"}
	if diff := cmp.Diff(want, paths); diff != "" {
		t.Errorf("problem paths (-want +got):\n%s", diff)
	}
}

// TestSidecarCIDRWarning: a trusted sidecar range beyond loopback is logged at start-up (TDD-05 §1).
func TestSidecarCIDRWarning(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		cidrs []string
		warn  bool
	}{
		{[]string{"127.0.0.1/32", "::1/128"}, false},
		{[]string{"127.0.0.0/8"}, false},
		{[]string{"127.0.0.1/32", "10.0.0.0/8"}, true},
		{[]string{"126.0.0.0/7"}, true},
		{[]string{"::/0"}, true},
		{[]string{"::1/127"}, true},
	} {
		var logs bytes.Buffer
		warnSidecars(slog.New(slog.NewTextHandler(&logs, nil)), tc.cidrs)
		if got := strings.Contains(logs.String(), "level=WARN"); got != tc.warn {
			t.Errorf("%v: warned %v, want %v\n%s", tc.cidrs, got, tc.warn, &logs)
		}
	}
}

// TestConfigCheckBadSidecarCIDR: config check refuses a trusted sidecar that is not a CIDR.
func TestConfigCheckBadSidecarCIDR(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	example, err := os.ReadFile("config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	const line = `trusted_sidecar_cidrs: [127.0.0.1/32, "::1/128"]`
	if !bytes.Contains(example, []byte(line)) {
		t.Fatalf("config.example.yaml has no line %q", line)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	bad := bytes.Replace(example, []byte(line), []byte(`trusted_sidecar_cidrs: [127.0.0.1, "::1/128"]`), 1)
	if err := os.WriteFile(path, bad, 0o600); err != nil { //nolint:gosec // a test file in a temporary directory
		t.Fatal(err)
	}
	out, err := runConfigCheck(t, path)
	if !errors.Is(err, errConfigInvalid) || !strings.Contains(out, "  - service_auth.mesh.trusted_sidecar_cidrs[0]: ") {
		t.Errorf("config check = %v\n%s", err, out)
	}
}

// introspect posts to the API's /v1/introspect with the XFCC header for identity, or none for "".
func introspect(t *testing.T, api, identity string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, api+"/v1/introspect", strings.NewReader("token=abc"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if identity != "" {
		req.Header.Set("X-Forwarded-Client-Cert", "URI="+identity)
	}
	req.Header.Set("Auth1-Actor", "staff:test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestServeServiceCaller: serve mounts the caller middleware. The example's caller, from loopback,
// passes the check to the stub's 501; no identity is 401; an identity without the scope is 403,
// audited and counted.
func TestServeServiceCaller(t *testing.T) {
	dsn := pgtest.DSN(t)
	api, metrics := startServeWithMetrics(t, append(dsnEnv(t, dsn), promoteAtOnce))
	waitReady(t, api, http.StatusOK, "ok", 5*time.Second)

	if code, body := introspect(t, api, "spiffe://cluster.local/ns/example/sa/reports"); code != http.StatusNotImplemented {
		t.Errorf("configured caller: %d %s, want 501", code, body)
	}
	if code, body := introspect(t, api, ""); code != http.StatusUnauthorized || !strings.Contains(body, `"TOKEN_INVALID"`) {
		t.Errorf("no identity: %d %s, want 401 TOKEN_INVALID", code, body)
	}
	if code, body := introspect(t, api, "spiffe://cluster.local/ns/other/sa/other"); code != http.StatusForbidden || !strings.Contains(body, `"CALLER_NOT_ALLOWED"`) {
		t.Errorf("unknown identity: %d %s, want 403 CALLER_NOT_ALLOWED", code, body)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var actorID, onBehalf, outcome, details string
	err = db.QueryRowContext(context.Background(), `SELECT actor_id, on_behalf, outcome, details::text FROM auth_audit
		WHERE action = 'service_call_denied' AND actor_kind = 'service'`).Scan(&actorID, &onBehalf, &outcome, &details)
	if err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if actorID != "spiffe://cluster.local/ns/other/sa/other" || onBehalf != "staff:test" || outcome != "failure" ||
		!strings.Contains(details, `"operation": "introspectToken"`) {
		t.Errorf("audit row: %q %q %q %s", actorID, onBehalf, outcome, details)
	}
	_, body := get(t, metrics+"/metrics")
	if !denialCounted(body, `caller="unknown"`, `scope="tokens:introspect"`) {
		t.Errorf("no denial counted in /metrics:\n%s", body)
	}
}

// denialCounted reports whether the /metrics body has an auth1_service_calls_denied_total series
// of 1 with every one of labels.
func denialCounted(body string, labels ...string) bool {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "auth1_service_calls_denied_total{") || !strings.HasSuffix(line, "} 1") {
			continue
		}
		all := true
		for _, l := range labels {
			all = all && strings.Contains(line, l)
		}
		if all {
			return true
		}
	}
	return false
}
