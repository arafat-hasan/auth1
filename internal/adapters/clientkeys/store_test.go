package clientkeys_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/clientkeys"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/testing/assertiontest"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

var _ app.ClientKeys = (*clientkeys.Store)(nil)

var t0 = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

// jwksServer is a TLS server of one client's JWKS that counts its requests. Its answer can change.
type jwksServer struct {
	*httptest.Server
	hits   atomic.Int32
	mu     sync.Mutex
	status int
	body   []byte
	delay  time.Duration
}

func newJWKSServer(t *testing.T, body []byte) *jwksServer {
	t.Helper()
	s := &jwksServer{status: http.StatusOK, body: body}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		status, body, delay := s.status, s.body, s.delay
		s.mu.Unlock()
		time.Sleep(delay)
		if status == http.StatusFound {
			http.Redirect(w, r, "/elsewhere", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) serve(status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.body = status, body
}

// uriStore is a store of client "reports" whose keys are at s, on a fake clock.
func uriStore(t *testing.T, s *jwksServer) (*clientkeys.Store, *fakes.Clock) {
	t.Helper()
	clock := fakes.NewClock(t0)
	st, err := clientkeys.New(clientkeys.Options{
		Clients: []clientkeys.Client{{ID: "reports", URI: s.URL + "/jwks.json"}},
		HTTP:    s.Client(), Clock: clock, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return st, clock
}

func key(t *testing.T, st *clientkeys.Store, kid string) error {
	t.Helper()
	pk, err := st.Key(context.Background(), "reports", kid)
	if err == nil && pk.Kid != kid {
		t.Fatalf("Key(%s) = %s", kid, pk.Kid)
	}
	return err
}

func TestURIFetchedAndCached(t *testing.T) {
	t.Parallel()
	c := assertiontest.NewClient(t, "reports", "ES256")
	s := newJWKSServer(t, c.JWKS())
	st, clock := uriStore(t, s)
	for range 10 {
		if err := key(t, st, c.Kid()); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Minute - time.Second)
	}
	if n := s.hits.Load(); n != 1 {
		t.Errorf("%d fetches within 10 min, want 1", n)
	}
}

func TestURIRefreshAfterTenMinutes(t *testing.T) {
	t.Parallel()
	c := assertiontest.NewClient(t, "reports", "ES256")
	s := newJWKSServer(t, c.JWKS())
	st, clock := uriStore(t, s)
	_ = key(t, st, c.Kid())
	clock.Advance(10*time.Minute - time.Microsecond)
	_ = key(t, st, c.Kid())
	if n := s.hits.Load(); n != 1 {
		t.Fatalf("%d fetches before 10 min, want 1", n)
	}
	clock.Advance(time.Microsecond)
	_ = key(t, st, c.Kid())
	if n := s.hits.Load(); n != 2 {
		t.Errorf("%d fetches at 10 min, want 2", n)
	}
}

// TestUnknownKidFloor: a flood of unknown kids refetches the set at most once a minute (TDD-05
// §2), and a key added since is found at the next allowed refetch.
func TestUnknownKidFloor(t *testing.T) {
	t.Parallel()
	c := assertiontest.NewClient(t, "reports", "ES256")
	s := newJWKSServer(t, c.JWKS())
	st, clock := uriStore(t, s)
	if err := key(t, st, c.Kid()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Minute)
	for i := range 100 {
		if err := key(t, st, "unknown"); !errors.Is(err, app.ErrUnknownClientKey) {
			t.Fatalf("unknown kid #%d: %v", i, err)
		}
	}
	if n := s.hits.Load(); n != 2 {
		t.Fatalf("%d fetches after 100 unknown kids, want 2", n)
	}
	rotated := assertiontest.NewClient(t, "reports", "RS256")
	s.serve(http.StatusOK, rotated.JWKS())
	clock.Advance(time.Minute - time.Microsecond)
	if err := key(t, st, rotated.Kid()); !errors.Is(err, app.ErrUnknownClientKey) {
		t.Fatalf("new kid within the minute: %v", err)
	}
	clock.Advance(time.Microsecond)
	if err := key(t, st, rotated.Kid()); err != nil {
		t.Fatalf("new kid after the minute: %v", err)
	}
	if n := s.hits.Load(); n != 3 {
		t.Errorf("%d fetches, want 3", n)
	}
}

// TestFetchErrorKeepsStale: a failed refresh keeps the cached keys.
func TestFetchErrorKeepsStale(t *testing.T) {
	t.Parallel()
	c := assertiontest.NewClient(t, "reports", "ES256")
	s := newJWKSServer(t, c.JWKS())
	st, clock := uriStore(t, s)
	_ = key(t, st, c.Kid())
	s.serve(http.StatusInternalServerError, nil)
	clock.Advance(11 * time.Minute)
	if err := key(t, st, c.Kid()); err != nil {
		t.Fatalf("stale key after a failed refresh: %v", err)
	}
	if n := s.hits.Load(); n != 2 {
		t.Errorf("%d fetches, want 2", n)
	}
}

// TestNoKeysUnavailable: with nothing cached, a failed fetch is ErrClientKeysUnavailable, for
// each way a fetch may fail.
func TestNoKeysUnavailable(t *testing.T) {
	t.Parallel()
	c := assertiontest.NewClient(t, "reports", "ES256")
	tests := map[string]func(s *jwksServer){
		"server error": func(s *jwksServer) { s.serve(http.StatusInternalServerError, c.JWKS()) },
		"not found":    func(s *jwksServer) { s.serve(http.StatusNotFound, c.JWKS()) },
		"redirect":     func(s *jwksServer) { s.serve(http.StatusFound, nil) },
		"over 64 KiB": func(s *jwksServer) {
			b := c.JWKS()
			s.serve(http.StatusOK, append(b[:len(b)-1], []byte(`,"pad":"`+strings.Repeat("x", 64<<10)+`"}`)...))
		},
		"not a JWKS": func(s *jwksServer) { s.serve(http.StatusOK, []byte("<html>")) },
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newJWKSServer(t, nil)
			setup(s)
			st, clock := uriStore(t, s)
			if err := key(t, st, c.Kid()); !errors.Is(err, app.ErrClientKeysUnavailable) {
				t.Fatalf("err = %v, want ErrClientKeysUnavailable", err)
			}
			if n := s.hits.Load(); n != 1 {
				t.Errorf("%d requests, want 1 (no redirect followed)", n)
			}
			// A failed fetch is retried no sooner than a minute later.
			s.serve(http.StatusOK, c.JWKS())
			_ = key(t, st, c.Kid())
			clock.Advance(time.Minute)
			if err := key(t, st, c.Kid()); err != nil {
				t.Fatalf("after a minute: %v", err)
			}
			if n := s.hits.Load(); n != 2 {
				t.Errorf("%d requests, want 2", n)
			}
		})
	}
}

// TestConcurrentKeyOneFetch: concurrent lookups for one client share one fetch.
func TestConcurrentKeyOneFetch(t *testing.T) {
	t.Parallel()
	c := assertiontest.NewClient(t, "reports", "ES256")
	s := newJWKSServer(t, c.JWKS())
	s.delay = 50 * time.Millisecond
	st, _ := uriStore(t, s)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if err := key(t, st, c.Kid()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := s.hits.Load(); n != 1 {
		t.Errorf("%d fetches, want 1", n)
	}
}

func TestUnknownClient(t *testing.T) {
	t.Parallel()
	s := newJWKSServer(t, nil)
	st, _ := uriStore(t, s)
	if _, err := st.Key(context.Background(), "billing", "k"); !errors.Is(err, app.ErrUnknownClientKey) {
		t.Errorf("err = %v, want ErrUnknownClientKey", err)
	}
	if n := s.hits.Load(); n != 0 {
		t.Errorf("%d fetches for an unknown client", n)
	}
}

// fileStore is a store of client "reports" whose keys are in the file at path, polled every
// 10 ms, logging to log.
func fileStore(t *testing.T, path string, log *syncBuffer) (*clientkeys.Store, error) {
	t.Helper()
	return clientkeys.New(clientkeys.Options{
		Clients:  []clientkeys.Client{{ID: "reports", File: path}},
		Clock:    fakes.NewClock(t0),
		Logger:   slog.New(slog.NewTextHandler(log, nil)),
		Interval: 10 * time.Millisecond,
	})
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestNewRefusesBadFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": filepath.Join(dir, "none.json"), "no usable key": bad} {
		if _, err := fileStore(t, path, &syncBuffer{}); err == nil || !strings.Contains(err.Error(), "reports") {
			t.Errorf("%s: err = %v, want one naming the client", name, err)
		}
	}
}

// TestFileReloadKeepsLastGood: Run picks up a changed file, and keeps the last good set when the
// file turns bad.
func TestFileReloadKeepsLastGood(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "reports.json")
	first := assertiontest.NewClient(t, "reports", "ES256")
	second := assertiontest.NewClient(t, "reports", "ES256")
	if err := os.WriteFile(path, first.JWKS(), 0o600); err != nil {
		t.Fatal(err)
	}
	log := &syncBuffer{}
	st, err := fileStore(t, path, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := key(t, st, first.Kid()); err != nil {
		t.Fatal(err)
	}
	if err := key(t, st, second.Kid()); !errors.Is(err, app.ErrUnknownClientKey) {
		t.Fatalf("second kid before the reload: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- st.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	if err := os.WriteFile(path, second.JWKS(), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return key(t, st, second.Kid()) == nil })
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return strings.Contains(log.String(), "client keys reload failed") })
	if err := key(t, st, second.Kid()); err != nil {
		t.Errorf("last good key after a bad file: %v", err)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHTTPClient(t *testing.T) {
	t.Parallel()
	c := clientkeys.HTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	switch {
	case c.Timeout != 5*time.Second:
		t.Errorf("timeout %s, want 5s", c.Timeout)
	case !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12:
		t.Errorf("transport %#v, want TLS 1.2 or later", c.Transport)
	case tr.Proxy != nil:
		t.Error("the fetch goes through a proxy")
	}
}
