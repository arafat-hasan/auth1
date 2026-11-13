package clientkeys

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arafat-hasan/auth1/internal/app"
)

// The timing of TDD-05 §2.
const (
	// CacheFor is how long a fetched key set is used before it is fetched again.
	CacheFor = 10 * time.Minute
	// RefetchFloor is the least time between two fetches of one client's jwks_uri, whether the
	// last failed or an unknown kid asks for a new one.
	RefetchFloor = time.Minute
	// FetchTimeout bounds a fetch.
	FetchTimeout = 5 * time.Second
	// DefaultInterval is how often Run re-reads the jwks_file of each client.
	DefaultInterval = 30 * time.Second
)

// Client is a service client and where its keys are: exactly one of File and URI.
type Client struct {
	ID   string
	File string // service_auth.client_credentials.clients[].jwks_file
	URI  string // service_auth.client_credentials.clients[].jwks_uri
}

// Options configure a Store.
type Options struct {
	Clients []Client
	// HTTP fetches jwks_uri; nil uses HTTPClient. Store refuses its redirects and, when it has no
	// timeout, sets FetchTimeout.
	HTTP   *http.Client
	Clock  app.Clock
	Logger *slog.Logger
	// Interval is how often Run re-reads the files; 0 is DefaultInterval.
	Interval time.Duration
}

// HTTPClient returns the client that fetches jwks_uri: FetchTimeout, TLS 1.2 or later against the
// system roots, no proxy (the fetch goes directly, not through the mesh) and no redirects.
func HTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the standard library's
	tr.Proxy = nil
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: FetchTimeout, CheckRedirect: noRedirect}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// keySet is a client's keys and when they were fetched (zero for a file).
type keySet struct {
	keys    map[string]app.PublicKey
	fetched time.Time
}

// source is one client's keys.
type source struct {
	Client
	set atomic.Pointer[keySet]

	mu        sync.Mutex // held while fetching URI, so one fetch is in flight
	attempted time.Time  // the last fetch, successful or not; under mu

	seen    [sha256.Size]byte // the file content last read, valid or not; Run's only
	readErr string            // the last file read error, logged once; Run's only
}

// Store implements app.ClientKeys. Build it with New.
type Store struct {
	sources  map[string]*source
	http     *http.Client
	clock    app.Clock
	logger   *slog.Logger
	interval time.Duration
}

// New returns a store of o.Clients' keys. It reads every jwks_file, and refuses one that cannot
// be read or holds no usable key, naming the client; jwks_uri is fetched when first needed.
func New(o Options) (*Store, error) {
	if o.Clock == nil || o.Logger == nil {
		return nil, errors.New("clientkeys: a clock and a logger are required")
	}
	hc := HTTPClient()
	if o.HTTP != nil {
		c := *o.HTTP
		c.CheckRedirect = noRedirect
		if c.Timeout == 0 {
			c.Timeout = FetchTimeout
		}
		hc = &c
	}
	s := &Store{sources: make(map[string]*source, len(o.Clients)), http: hc, clock: o.Clock, logger: o.Logger, interval: o.Interval}
	if s.interval <= 0 {
		s.interval = DefaultInterval
	}
	for _, c := range o.Clients {
		src := &source{Client: c}
		if c.File != "" {
			data, err := readFile(c.File)
			if err != nil {
				return nil, fmt.Errorf("client %s: jwks_file: %w", c.ID, err)
			}
			keys, err := Parse(data)
			if err != nil {
				return nil, fmt.Errorf("client %s: jwks_file %s: %w", c.ID, c.File, err)
			}
			src.seen = sha256.Sum256(data)
			src.set.Store(&keySet{keys: keys})
		}
		s.sources[c.ID] = src
	}
	return s, nil
}

// Key implements app.ClientKeys. For a jwks_uri client it fetches the set when none is cached or
// it is CacheFor old, and refetches it for an unknown kid; either fetch happens at most once per
// RefetchFloor, one at a time. A failed fetch keeps the cached set.
func (s *Store) Key(ctx context.Context, clientID, kid string) (app.PublicKey, error) {
	src, ok := s.sources[clientID]
	if !ok {
		return app.PublicKey{}, app.ErrUnknownClientKey
	}
	if src.URI == "" {
		return lookup(src.set.Load(), kid)
	}
	if set := src.set.Load(); set != nil && s.fresh(set) {
		if pk, ok := set.keys[kid]; ok {
			return pk, nil
		}
	}

	src.mu.Lock()
	defer src.mu.Unlock()
	set := src.set.Load() // a concurrent fetch may have refreshed it
	if set != nil && s.fresh(set) {
		if pk, ok := set.keys[kid]; ok {
			return pk, nil
		}
	}
	now := s.clock.Now()
	if src.attempted.IsZero() || now.Sub(src.attempted) >= RefetchFloor {
		src.attempted = now
		// The fetch outlives a caller that hangs up, so the callers waiting on it get its result.
		keys, err := s.fetch(context.WithoutCancel(ctx), src.URI)
		if err != nil {
			s.logger.LogAttrs(ctx, slog.LevelWarn, "client keys fetch failed",
				slog.String("client", clientID), slog.String("error", err.Error()))
		} else {
			set = &keySet{keys: keys, fetched: now}
			src.set.Store(set)
		}
	}
	if set == nil {
		return app.PublicKey{}, app.ErrClientKeysUnavailable
	}
	return lookup(set, kid)
}

func (s *Store) fresh(set *keySet) bool { return s.clock.Now().Sub(set.fetched) < CacheFor }

func lookup(set *keySet, kid string) (app.PublicKey, error) {
	if pk, ok := set.keys[kid]; ok {
		return pk, nil
	}
	return app.PublicKey{}, app.ErrUnknownClientKey
}

// fetch gets and parses the JWKS at uri: a 200 of at most MaxSize. Its errors hold no body.
func (s *Store) fetch(ctx context.Context, uri string) (map[string]app.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return Parse(data)
}

// readFile reads a jwks_file, refusing one over MaxSize without reading it all.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the path comes from the configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, MaxSize+1))
}

// Run re-reads each jwks_file every interval until ctx ends, then returns nil. A changed file
// with a usable key replaces the client's set; one that cannot be read or is invalid keeps the
// last good set and is logged as an error once for each distinct content (TDD-05 §2).
func (s *Store) Run(ctx context.Context) error {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			for _, src := range s.sources {
				if src.File != "" {
					s.reload(ctx, src)
				}
			}
		}
	}
}

// reload reads src's file once and swaps its set if the content changed and is valid.
func (s *Store) reload(ctx context.Context, src *source) {
	fail := func(msg string) {
		s.logger.LogAttrs(ctx, slog.LevelError, "client keys reload failed",
			slog.String("client", src.ID), slog.String("file", src.File), slog.String("error", msg))
	}
	data, err := readFile(src.File)
	if err != nil {
		if msg := err.Error(); msg != src.readErr {
			src.readErr = msg
			fail(msg)
		}
		return
	}
	src.readErr = ""
	sum := sha256.Sum256(data)
	if sum == src.seen {
		return
	}
	src.seen = sum
	keys, err := Parse(data)
	if err != nil {
		fail(err.Error())
		return
	}
	src.set.Store(&keySet{keys: keys})
	s.logger.LogAttrs(ctx, slog.LevelInfo, "client keys reloaded",
		slog.String("client", src.ID), slog.String("file", src.File), slog.Int("keys", len(keys)))
}
