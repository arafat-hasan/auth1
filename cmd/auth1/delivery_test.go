package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/arafat-hasan/auth1/internal/adapters/delivery/capture"
	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// TestNewDeliveryRefusesCaptureOutsideDevelopment is T-17 at the wiring: even a configuration that
// skipped Validate gets no capture adapter outside development.
func TestNewDeliveryRefusesCaptureOutsideDevelopment(t *testing.T) {
	t.Parallel()
	for _, env := range []config.Environment{config.EnvTest, config.EnvStaging, config.EnvProduction} {
		cfg := config.Default()
		cfg.App.Environment = env
		cfg.Delivery.Adapter = config.DeliveryCapture
		d, dev, err := newDelivery(&cfg, unavailableResolver{}, system.Clock{})
		if err == nil || !strings.Contains(err.Error(), "delivery.adapter") || d != nil || dev != nil {
			t.Errorf("%s: newDelivery = %v, %v, %v; want an error naming delivery.adapter", env, d, dev != nil, err)
		}
	}

	cfg := config.Default()
	cfg.App.Environment = config.EnvDevelopment
	cfg.Delivery.Adapter = config.DeliveryCapture
	d, dev, err := newDelivery(&cfg, unavailableResolver{}, system.Clock{})
	if _, ok := d.(*capture.Inbox); !ok || dev == nil || err != nil {
		t.Errorf("development: newDelivery = %T, %v, %v; want the capture inbox and its routes", d, dev != nil, err)
	}

	cfg.Delivery.Adapter = config.DeliveryNotification
	if d, dev, err := newDelivery(&cfg, unavailableResolver{}, system.Clock{}); d != nil || dev != nil || err != nil {
		t.Errorf("notification: newDelivery = %v, %v, %v; want nothing until WP-44", d, dev != nil, err)
	}
}

// TestServeT17Capture is acceptance test T-17 for serve: production with the capture adapter is
// refused before anything binds.
func TestServeT17Capture(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	restoreDefaults(t)

	var bound atomic.Bool
	deps := serveDeps{listen: func(string, string) (net.Listener, error) {
		bound.Store(true)
		return nil, errors.New("must not bind")
	}}
	var out bytes.Buffer
	env := []string{"AUTH1_APP_ENVIRONMENT=production", "AUTH1_DELIVERY_ADAPTER=capture"}
	err := newTestServeCmd(deps, &out, env, "--config", "config.example.yaml")(context.Background())
	if !errors.Is(err, errConfigInvalid) {
		t.Fatalf("serve = %v, want errConfigInvalid\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "  - delivery.adapter: capture is for development only\n") {
		t.Errorf("output does not refuse capture:\n%s", out.String())
	}
	if bound.Load() {
		t.Error("serve bound a listener in production with capture")
	}
}

// TestServeCaptureInDevelopment: in development with capture, serve answers GET /dev/messages at
// the root; with another adapter it does not.
func TestServeCaptureInDevelopment(t *testing.T) {
	env := append(dsnEnv(t, pgtest.DSN(t)), promoteAtOnce, "AUTH1_DELIVERY_ADAPTER=capture")
	api := startServe(t, env)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, api+"/dev/messages?to=a@example.org", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" ||
		strings.TrimSpace(string(b)) != `{"messages":[]}` {
		t.Errorf("GET /dev/messages = %d %v %s", resp.StatusCode, resp.Header, b)
	}
}

// TestConfigCheckMessageTypes checks that delivery.types is checked against the purposes after
// Validate (TDD-06 §7). It runs from the repository root, like TestConfigCheckExample.
func TestConfigCheckMessageTypes(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))

	example, err := os.ReadFile("config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^  types: \{\}.*$`)
	if !re.Match(example) {
		t.Fatal("config.example.yaml has no delivery.types line")
	}
	types := "  types: { nope: x.nope, sign_in_code: \"\", password_reset_link: x.reset }"
	path := filepath.Join(t.TempDir(), "types.yaml")
	if err := os.WriteFile(path, re.ReplaceAll(example, []byte(types)), 0o600); err != nil { //nolint:gosec // a test file in a temporary directory
		t.Fatal(err)
	}
	out, err := runConfigCheck(t, path)
	if !errors.Is(err, errConfigInvalid) {
		t.Fatalf("config check error = %v, want errConfigInvalid\n%s", err, out)
	}
	want := "configuration has 2 problem(s):\n" +
		"  - delivery.types.nope: unknown purpose\n" +
		"  - delivery.types.sign_in_code: the message type is empty\n"
	if !strings.HasPrefix(out, want) {
		t.Errorf("output:\n%s\nwant it to start with:\n%s", out, want)
	}

	var outServe bytes.Buffer
	err = newTestServeCmd(serveDeps{}, &outServe, slices.Clone(developmentEnv), "--config", path)(context.Background())
	if !errors.Is(err, errConfigInvalid) || !strings.Contains(outServe.String(), "delivery.types.nope") {
		t.Errorf("serve = %v, want the delivery.types problems\n%s", err, outServe.String())
	}
}
