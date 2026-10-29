package crypto_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
)

// logBuffer is a concurrency-safe log sink.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logBuffer) logger() *slog.Logger { return slog.New(slog.NewTextHandler(l, nil)) }

// replaceFile replaces path's content by renaming a temporary file over it, as a secret mount's
// symlink swap does: a reader sees the old content or the new, never a mix. It returns errors
// rather than failing the test, so goroutines other than the test's can call it.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// writeAtomic is replaceFile that fails the test on error. Call it from the test's goroutine only.
func writeAtomic(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := replaceFile(path, data); err != nil {
		t.Fatal(err)
	}
}

// watch starts a WatchedKeyring on a new file holding data, polling every interval until the test
// ends.
func watch(t *testing.T, data []byte, interval time.Duration, logs *logBuffer) (*crypto.WatchedKeyring, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyring.yaml")
	writeAtomic(t, path, data)
	w, err := crypto.NewWatchedKeyring(path, crypto.StateDecrypt, logs.logger(), crypto.WithInterval(interval))
	if err != nil {
		t.Fatalf("NewWatchedKeyring: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	return w, path
}

// eventually waits up to 2 s for cond.
func eventually(t *testing.T, cond func() bool) bool {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

func TestWatchedKeyringReloads(t *testing.T) {
	t.Parallel()
	logs := &logBuffer{}
	w, path := watch(t, keyringYAML(entry{1, 1, "active"}), 10*time.Millisecond, logs)
	if id, _ := w.Current().Active(); id != 1 {
		t.Fatalf("active %d, want 1", id)
	}
	writeAtomic(t, path, keyringYAML(entry{1, 1, "decrypt"}, entry{2, 50, "active"}))
	if !eventually(t, func() bool { id, _ := w.Current().Active(); return id == 2 }) {
		t.Fatal("the new keyring was not loaded")
	}
	if !eventually(t, func() bool { return strings.Contains(logs.String(), "keyring reloaded") }) {
		t.Errorf("no reload logged: %s", logs)
	}
}

func TestWatchedKeyringKeepsLastGood(t *testing.T) {
	t.Parallel()
	logs := &logBuffer{}
	w, path := watch(t, keyringYAML(entry{1, 1, "active"}), 5*time.Millisecond, logs)
	good := w.Current()
	bad := [][]byte{
		keyringYAML(entry{1, 1, "active"}, entry{2, 50, "active"}),
		{},
		[]byte("keys: [\n"),
	}
	for i, data := range bad {
		writeAtomic(t, path, data)
		if !eventually(t, func() bool { return strings.Count(logs.String(), "level=ERROR") == i+1 }) {
			t.Fatalf("bad file %d: not logged once: %s", i, logs)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if !eventually(t, func() bool { return strings.Count(logs.String(), "level=ERROR") == len(bad)+1 }) {
		t.Fatalf("missing file not logged: %s", logs)
	}
	time.Sleep(50 * time.Millisecond) // several more polls: no repeated records
	out := logs.String()
	if n := strings.Count(out, "level=ERROR"); n != len(bad)+1 {
		t.Errorf("%d error records, want one per bad content (%d): %s", n, len(bad)+1, out)
	}
	if w.Current() != good {
		t.Error("an invalid file replaced the keyring")
	}
	for _, want := range []string{path, "several active keys", "no keys", "not valid YAML", "no such file"} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %q: %s", want, out)
		}
	}
	for _, first := range []byte{1, 50} {
		if strings.Contains(out, b64(keyBytes(first))) {
			t.Error("log contains a key")
		}
	}

	// A valid file after the bad ones is loaded.
	writeAtomic(t, path, keyringYAML(entry{1, 1, "decrypt"}, entry{2, 50, "active"}))
	if !eventually(t, func() bool { id, _ := w.Current().Active(); return id == 2 }) {
		t.Error("the valid file was not loaded after the bad ones")
	}
}

func TestWatchedKeyringUnchanged(t *testing.T) {
	t.Parallel()
	logs := &logBuffer{}
	data := keyringYAML(entry{1, 1, "active"})
	w, path := watch(t, data, 5*time.Millisecond, logs)
	first := w.Current()
	writeAtomic(t, path, data)
	time.Sleep(50 * time.Millisecond)
	if w.Current() != first {
		t.Error("rewriting the same content swapped the keyring")
	}
	if strings.Contains(logs.String(), "reloaded") {
		t.Errorf("unchanged content logged a reload: %s", logs)
	}
}

func TestNewWatchedKeyringRefusesInvalid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.yaml")
	writeAtomic(t, path, keyringYAML(entry{1, 1, "decrypt"}))
	for _, p := range []string{path, filepath.Join(dir, "missing.yaml")} {
		_, err := crypto.NewWatchedKeyring(p, crypto.StateDecrypt, slog.New(slog.DiscardHandler))
		if err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("NewWatchedKeyring(%s) = %v, want an error naming the file", p, err)
		}
	}
}

func TestWatchedKeyringRunStops(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keyring.yaml")
	writeAtomic(t, path, keyringYAML(entry{1, 1, "active"}))
	w, err := crypto.NewWatchedKeyring(path, crypto.StateDecrypt, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop when its context ended")
	}
}

func TestDefaultReloadInterval(t *testing.T) {
	t.Parallel()
	if crypto.DefaultReloadInterval != 30*time.Second {
		t.Errorf("DefaultReloadInterval = %v, want 30s (TDD-08 §7)", crypto.DefaultReloadInterval)
	}
}
