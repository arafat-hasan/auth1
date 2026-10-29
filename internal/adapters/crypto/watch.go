package crypto

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// DefaultReloadInterval is how often a WatchedKeyring re-reads its file (TDD-08 §7: keyring sync,
// a 30 s poll).
const DefaultReloadInterval = 30 * time.Second

// WatchedKeyring is a keyring file that is re-read while the process runs (SDD D-18, TDD-08 §4).
// Current gives the last valid keyring loaded, through one atomic load, so a caller never sees a
// half-loaded keyring (R-1). The file is polled rather than watched for events, because mounted
// secrets change by a symlink swap that file events do not reliably report.
type WatchedKeyring struct {
	path       string
	otherState string
	logger     *slog.Logger
	interval   time.Duration

	current atomic.Pointer[Keyring]

	// Run's state, touched only by its goroutine.
	seen    [sha256.Size]byte // the content last read, valid or not
	readErr string            // the last read error, logged once
}

// WatchOption configures a WatchedKeyring.
type WatchOption func(*WatchedKeyring)

// WithInterval sets how often the file is re-read (DefaultReloadInterval by default).
func WithInterval(d time.Duration) WatchOption {
	return func(w *WatchedKeyring) { w.interval = d }
}

// NewWatchedKeyring loads the keyring file at path (see ParseKeyring for otherState). A file that
// cannot be read or is invalid is an error, so the process refuses to start (TDD-08 §3.1). Call
// Run to follow changes to the file.
func NewWatchedKeyring(path, otherState string, logger *slog.Logger, opts ...WatchOption) (*WatchedKeyring, error) {
	w := &WatchedKeyring{path: path, otherState: otherState, logger: logger, interval: DefaultReloadInterval}
	for _, o := range opts {
		o(w)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keyring: %w", err)
	}
	defer clear(data)
	k, err := ParseKeyring(data, otherState)
	if err != nil {
		return nil, fmt.Errorf("keyring file %s: %w", path, err)
	}
	w.seen = sha256.Sum256(data)
	w.current.Store(k)
	return w, nil
}

// Current returns the keyring in use: the last valid one loaded.
func (w *WatchedKeyring) Current() *Keyring { return w.current.Load() }

// Run re-reads the file every interval until ctx ends, then returns nil. A changed file that is
// valid replaces the keyring; one that cannot be read or is invalid leaves the last valid keyring
// in use and is logged as an error, naming the file and the reason (never a key), once for each
// distinct content.
func (w *WatchedKeyring) Run(ctx context.Context) error {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			w.reload(ctx)
		}
	}
}

// reload reads the file once and swaps the keyring if the content changed and is valid.
func (w *WatchedKeyring) reload(ctx context.Context) {
	data, err := os.ReadFile(w.path)
	if err != nil {
		if msg := err.Error(); msg != w.readErr {
			w.readErr = msg
			w.logger.LogAttrs(ctx, slog.LevelError, "keyring reload failed",
				slog.String("file", w.path), slog.String("error", msg))
		}
		return
	}
	defer clear(data)
	w.readErr = ""
	sum := sha256.Sum256(data)
	if sum == w.seen {
		return
	}
	w.seen = sum
	k, err := ParseKeyring(data, w.otherState)
	if err != nil {
		w.logger.LogAttrs(ctx, slog.LevelError, "keyring reload failed",
			slog.String("file", w.path), slog.String("error", err.Error()))
		return
	}
	w.current.Store(k)
	w.logger.LogAttrs(ctx, slog.LevelInfo, "keyring reloaded",
		slog.String("file", w.path), slog.Any("keyring", k))
}
