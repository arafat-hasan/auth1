package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/http/server"
)

// testDeps binds every listener on 127.0.0.1:0 and reports each bound address on addrs, keyed by
// the configured address.
func testDeps(addrs chan<- [2]string) serveDeps {
	return serveDeps{
		listen: func(network, addr string) (net.Listener, error) {
			ln, err := net.Listen(network, "127.0.0.1:0")
			if err == nil {
				addrs <- [2]string{addr, ln.Addr().String()}
			}
			return ln, err
		},
		drainDelay:       300 * time.Millisecond,
		shutdownTimeout:  5 * time.Second,
		telemetryTimeout: 5 * time.Second,
	}
}

// waitDraining polls url until it answers 503, since the drain begins on the server's goroutine
// shortly after the context is cancelled.
func waitDraining(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(200 * time.Millisecond) // within testDeps' drain delay
	for {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET %s: still %d after the drain began", url, resp.StatusCode)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStopFitsGracePeriod(t *testing.T) {
	t.Parallel()

	// Kubernetes' default terminationGracePeriodSeconds; SIGKILL follows it.
	const grace = 30 * time.Second
	if total := drainDelay + shutdownTimeout + telemetryTimeout; total >= grace {
		t.Errorf("stop sequence takes up to %v, want under %v", total, grace)
	}
	if shutdownTimeout < server.WriteTimeout {
		t.Errorf("shutdownTimeout %v is shorter than the write timeout %v", shutdownTimeout, server.WriteTimeout)
	}
}

func newTestServeCmd(deps serveDeps, out io.Writer, args ...string) func(ctx context.Context) error {
	cmd := newServeCmd(func() []string { return nil }, buildInfo{Version: "v-test"}, deps)
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs(args)
	return cmd.ExecuteContext
}

func TestServeRefusesInvalidConfig(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(path, []byte("tokens:\n  access_ttl: 1h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var bound atomic.Bool
	deps := serveDeps{listen: func(string, string) (net.Listener, error) {
		bound.Store(true)
		return nil, errors.New("must not bind")
	}}
	var out bytes.Buffer
	err := newTestServeCmd(deps, &out, "--config", path)(context.Background())
	if !errors.Is(err, errConfigInvalid) {
		t.Fatalf("serve = %v, want errConfigInvalid\n%s", err, out.String())
	}
	for _, p := range []string{"tokens.access_ttl", "http.issuer", "clients"} {
		if !strings.Contains(out.String(), "  - "+p+": ") {
			t.Errorf("output does not name %s:\n%s", p, out.String())
		}
	}
	if bound.Load() {
		t.Error("serve bound a listener with an invalid configuration")
	}
}

func TestServeRequiresConfig(t *testing.T) {
	t.Parallel()

	err := newTestServeCmd(serveDeps{}, &bytes.Buffer{})(context.Background())
	if err == nil {
		t.Fatal("serve without --config: want an error")
	}
}

// TestServeBindFailure runs from the repository root, where the example's secret paths resolve.
func TestServeBindFailure(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	restoreDefaults(t)

	tests := []struct{ failAddr, wantKey string }{
		{":8080", `http.listen ":8080"`},
		{":9090", `telemetry.metrics_listen ":9090"`},
	}
	for _, tt := range tests {
		var opened []net.Listener
		deps := serveDeps{
			listen: func(network, addr string) (net.Listener, error) {
				if addr == tt.failAddr {
					return nil, errors.New("address already in use")
				}
				ln, err := net.Listen(network, "127.0.0.1:0")
				opened = append(opened, ln)
				return ln, err
			},
			drainDelay: time.Millisecond, shutdownTimeout: time.Second, telemetryTimeout: time.Second,
		}
		err := newTestServeCmd(deps, &bytes.Buffer{}, "--config", "config.example.yaml")(context.Background())
		if err == nil || !strings.Contains(err.Error(), tt.wantKey) || !strings.Contains(err.Error(), "address already in use") {
			t.Errorf("fail %s: serve = %v, want the %s bind error", tt.failAddr, err, tt.wantKey)
		}
		for _, ln := range opened {
			_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)) // an open listener must not block the test
			if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("fail %s: listener %s was left open", tt.failAddr, ln.Addr())
			}
		}
	}
}

func TestServeRuns(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	restoreDefaults(t)

	addrs := make(chan [2]string, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := newTestServeCmd(testDeps(addrs), &bytes.Buffer{}, "--config", "config.example.yaml")
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()

	bound := map[string]string{}
	for range 2 {
		select {
		case a := <-addrs:
			bound[a[0]] = a[1]
		case err := <-done:
			t.Fatalf("serve returned early: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("serve did not bind its listeners")
		}
	}
	api, metrics := "http://"+bound[":8080"], "http://"+bound[":9090"]

	expect := func(url string, code int, contentType, contains string) string {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != code {
			t.Errorf("GET %s: status %d, want %d: %s", url, resp.StatusCode, code, b)
		}
		if contentType != "" && resp.Header.Get("Content-Type") != contentType {
			t.Errorf("GET %s: Content-Type %q, want %q", url, resp.Header.Get("Content-Type"), contentType)
		}
		if !strings.Contains(string(b), contains) {
			t.Errorf("GET %s: body does not contain %q: %s", url, contains, b)
		}
		return string(b)
	}
	expect(api+"/livez", 200, "application/json", `"ok"`)
	expect(api+"/readyz", 200, "application/json", `"draining"`)
	expect(api+"/nope", 404, "application/problem+json", `"NOT_FOUND"`)
	expect(metrics+"/metrics", 200, "", "http_server_request_duration_seconds_bucket")

	cancel()
	// Within the drain delay the API still answers, and /readyz fails once the drain has begun.
	waitDraining(t, api+"/readyz")
	body := expect(api+"/readyz", 503, "application/json", "")
	var ready struct {
		Checks []struct{ Name, Status string } `json:"checks"`
	}
	if err := json.Unmarshal([]byte(body), &ready); err != nil || len(ready.Checks) != 1 ||
		ready.Checks[0].Name != "draining" || ready.Checks[0].Status != "failing" {
		t.Errorf("/readyz while draining: %s", body)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}

// restoreDefaults puts back the default logger, which serve replaces.
func restoreDefaults(t *testing.T) {
	t.Helper()
	logger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(logger) })
}
