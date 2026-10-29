package keyring

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/arafat-hasan/auth1/internal/app"
)

const (
	// defaultPollInterval is how often the keyring is reloaded (TDD-04 §5.2, TDD-08 §7).
	defaultPollInterval = 30 * time.Second
	// retiredGrace is how long a retired key stays in the JWKS after the access-token lifetime.
	retiredGrace = 5 * time.Minute
)

var (
	_ app.TokenSigner = (*Keyring)(nil)
	_ app.PublicKeys  = (*Keyring)(nil)
)

// The readiness failures.
var (
	errNotSynced = errors.New("the signing keyring has not synced with the database")
	errNoSigner  = errors.New("no signing key may sign")
)

// Options are a Keyring's settings.
type Options struct {
	MinPublishBeforeUse time.Duration       // keys.min_publish_before_use
	AccessTTL           time.Duration       // tokens.access_ttl: retired keys stay AccessTTL + 5 min
	Logger              *slog.Logger        // nil for slog.Default()
	Keys                metric.Float64Gauge // auth1_jwks_keys, by state; nil for none
	PollInterval        time.Duration       // 0 for 30 s
}

// Keyring is the signing keyring (TDD-04 §5). It implements app.TokenSigner and app.PublicKeys.
// Its state is one immutable value behind an atomic pointer, so a reader never sees half of a
// reload. It is safe for concurrent use.
type Keyring struct {
	path  string
	store app.SigningKeyStore
	o     Options

	mu     sync.Mutex // serialises Reload
	file   *File      // the last valid file read
	digest [sha256.Size]byte

	cur atomic.Pointer[state] // nil before the first sync
}

// state is what a sync decided. It is never changed once stored.
type state struct {
	signer    *Key // nil when no key may sign
	published []app.PublicKey
	byKid     map[string]app.PublicKey
}

// New loads the keyring file at path, failing when it is invalid, and syncs it once. A failed sync
// is logged, and the keyring stays not ready until a Reload succeeds.
func New(ctx context.Context, path string, store app.SigningKeyStore, o Options) (*Keyring, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.PollInterval <= 0 {
		o.PollInterval = defaultPollInterval
	}
	src, err := read(path)
	if err != nil {
		return nil, err
	}
	f, err := src.parse()
	if err != nil {
		return nil, err
	}
	k := &Keyring{path: path, store: store, o: o, file: f, digest: src.digest}
	k.mu.Lock()
	defer k.mu.Unlock()
	_ = k.sync(ctx) // logged
	return k, nil
}

// Run reloads the keyring every poll interval until ctx ends, then returns nil. Failures are
// logged by Reload; the keyring keeps its last state.
func (k *Keyring) Run(ctx context.Context) error {
	t := time.NewTicker(k.o.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			_ = k.Reload(ctx)
		}
	}
}

// Reload reads the keyring file and its PEM files again, parses them when their content changed,
// and runs the TDD-04 §5.2 sync. An invalid file is logged and the previous one kept (and still
// synced); a failed sync is logged and the previous state kept. It returns what failed.
func (k *Keyring) Reload(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	var invalid error
	src, err := read(k.path)
	if err == nil && src.digest != k.digest {
		var f *File
		if f, err = src.parse(); err == nil {
			k.file, k.digest = f, src.digest
			k.o.Logger.InfoContext(ctx, "signing keyring changed", "keyring_file", k.path, "keys", f.Keys)
		}
	}
	if err != nil {
		k.o.Logger.ErrorContext(ctx, "signing keyring invalid", "keyring_file", k.path, "error", err)
		invalid = err
	}
	return errors.Join(invalid, k.sync(ctx))
}

// sync runs TDD-04 §5.2 for k.file and stores the state it decides. On a store failure it logs
// and keeps the previous state. k.mu is held.
func (k *Keyring) sync(ctx context.Context) error {
	s, err := k.decide(ctx, k.file)
	if err != nil {
		k.o.Logger.ErrorContext(ctx, "signing keyring sync failed", "keyring_file", k.path, "error", err)
		return err
	}
	k.cur.Store(s)
	k.record(ctx, s)
	return nil
}

// decide runs the three steps and the JWKS window against the store.
func (k *Keyring) decide(ctx context.Context, f *File) (*state, error) {
	recs := make([]app.SigningKeyRecord, len(f.Keys))
	for i, key := range f.Keys {
		recs[i] = app.SigningKeyRecord{Kid: key.Kid, Alg: key.Alg}
	}
	if err := k.store.Publish(ctx, recs); err != nil {
		return nil, err
	}

	active := f.Active()
	ok, err := k.store.Activate(ctx, active.Kid, k.o.MinPublishBeforeUse)
	if err != nil {
		return nil, err
	}
	var signer *Key
	if ok {
		signer = &active
	} else {
		var others []string
		for _, key := range f.Keys {
			if key.Kid != active.Kid {
				others = append(others, key.Kid)
			}
		}
		prev, err := k.store.LatestActivated(ctx, others)
		if err != nil {
			return nil, err
		}
		if i := slices.IndexFunc(f.Keys, func(key Key) bool { return key.Kid == prev }); i >= 0 {
			signer = &f.Keys[i]
		}
		k.o.Logger.ErrorContext(ctx, "signing key not promotable",
			"keyring_file", k.path, "kid", active.Kid, "signing_kid", prev)
	}

	var retired, retire []string
	for _, key := range f.Keys {
		if key.State != StateRetired {
			continue
		}
		retired = append(retired, key.Kid)
		if signer == nil || key.Kid != signer.Kid {
			retire = append(retire, key.Kid)
		}
	}
	if err := k.store.Retire(ctx, retire); err != nil {
		return nil, err
	}
	inWindow, err := k.store.Retiring(ctx, retired, k.o.AccessTTL+retiredGrace)
	if err != nil {
		return nil, err
	}

	s := &state{signer: signer, byKid: map[string]app.PublicKey{}}
	for _, key := range f.Keys {
		if key.State == StateRetired && !slices.Contains(inWindow, key.Kid) {
			continue
		}
		pk := app.PublicKey{Kid: key.Kid, Alg: key.Alg, Key: key.Public}
		s.published = append(s.published, pk)
		s.byKid[key.Kid] = pk
	}
	return s, nil
}

// record sets auth1_jwks_keys for each state from the published set.
func (k *Keyring) record(ctx context.Context, s *state) {
	if k.o.Keys == nil {
		return
	}
	counts := map[State]int{}
	for _, key := range k.file.Keys {
		if _, ok := s.byKid[key.Kid]; ok {
			counts[key.State]++
		}
	}
	for _, st := range []State{StateNext, StateActive, StateRetired} {
		k.o.Keys.Record(ctx, float64(counts[st]), metric.WithAttributes(attribute.String("state", string(st))))
	}
}

// Sign implements app.TokenSigner.
func (k *Keyring) Sign(payload []byte, typ string) (string, error) {
	s := k.cur.Load()
	if s == nil || s.signer == nil {
		return "", app.ErrNoSigningKey
	}
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, s.signer.Kid); err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	if err := hdr.Set(jws.TypeKey, typ); err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	alg := jwa.RS256()
	if s.signer.Alg == AlgES256 {
		alg = jwa.ES256()
	}
	token, err := jws.Sign(payload, jws.WithKey(alg, s.signer.private, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", fmt.Errorf("sign with %s: %w", s.signer.Kid, err)
	}
	return string(token), nil
}

// Key implements app.PublicKeys.
func (k *Keyring) Key(kid string) (app.PublicKey, bool) {
	s := k.cur.Load()
	if s == nil {
		return app.PublicKey{}, false
	}
	pk, ok := s.byKid[kid]
	return pk, ok
}

// Published implements app.PublicKeys.
func (k *Keyring) Published() ([]app.PublicKey, bool) {
	s := k.cur.Load()
	if s == nil {
		return nil, false
	}
	return slices.Clone(s.published), true
}

// Ready is the keyring readiness check: it fails before the first sync and while no key may sign.
func (k *Keyring) Ready(context.Context) error {
	s := k.cur.Load()
	switch {
	case s == nil:
		return errNotSynced
	case s.signer == nil:
		return errNoSigner
	}
	return nil
}

// String returns "signing keyring <path>", without key material.
func (k *Keyring) String() string { return "signing keyring " + k.path }

// GoString implements fmt.GoStringer, without the key material.
func (k *Keyring) GoString() string { return "&keyring.Keyring{" + k.path + "}" }

// Format implements fmt.Formatter for every verb, without the key material.
func (k *Keyring) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// LogValue implements slog.LogValuer, without the key material.
func (k *Keyring) LogValue() slog.Value { return slog.GroupValue(slog.String("keyring_file", k.path)) }
