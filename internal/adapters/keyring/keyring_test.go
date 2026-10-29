package keyring

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

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/uptrace/bun"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

const (
	minPublish = 15 * time.Minute
	accessTTL  = 15 * time.Minute
)

// logBuffer collects log output from concurrent goroutines.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// env is one database shared by the keyring instances of a test (the replicas), and a keyring
// file they all read.
type env struct {
	store *postgres.SigningKeys // as auth1_app
	su    *bun.DB               // superuser, for moving the stored times
	path  string
	logs  *logBuffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dsn := pgtest.DSN(t)
	open := func(dsn string) *bun.DB {
		file := filepath.Join(t.TempDir(), "dsn")
		if err := os.WriteFile(file, []byte(dsn), 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := postgres.Open(config.Database{DSNFile: config.NewSecretFile(file), MaxConns: 4, AcquireTimeout: 2 * time.Second}, config.EnvDevelopment)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	return &env{
		store: postgres.NewSigningKeys(open(pgtest.As(t, dsn, pgtest.App))),
		su:    open(dsn),
		path:  filepath.Join(t.TempDir(), "keyring.yaml"),
		logs:  &logBuffer{},
	}
}

// write writes the keyring file.
func (e *env) write(t *testing.T, specs []spec) {
	t.Helper()
	writeKeyring(t, filepath.Dir(e.path), specs, false)
}

// replica starts a keyring instance on the shared database and file.
func (e *env) replica(t *testing.T) *Keyring {
	t.Helper()
	return e.replicaWith(t, e.store, nil)
}

func (e *env) replicaWith(t *testing.T, store app.SigningKeyStore, mp *sdkmetric.MeterProvider) *Keyring {
	t.Helper()
	o := Options{
		MinPublishBeforeUse: minPublish, AccessTTL: accessTTL,
		Logger: slog.New(slog.NewJSONHandler(e.logs, nil)),
	}
	if mp != nil {
		g, err := mp.Meter("test").Float64Gauge("auth1_jwks_keys")
		if err != nil {
			t.Fatal(err)
		}
		o.Keys = g
	}
	k, err := New(t.Context(), e.path, store, o)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// exec runs a statement as superuser.
func (e *env) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := e.su.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}

// promotable moves kid's first publication back by min_publish_before_use: the effect of
// "auth1 keys force-activate" (TDD-04 §5.3).
func (e *env) promotable(t *testing.T, kid string) {
	t.Helper()
	e.exec(t, "UPDATE signing_keys SET first_published_at = now() - make_interval(secs => ?) WHERE kid = ?",
		minPublish.Seconds(), kid)
}

func (e *env) retiredAt(t *testing.T, kid string) (time.Time, bool) {
	t.Helper()
	var at *time.Time
	if err := e.su.QueryRowContext(t.Context(), "SELECT retired_at FROM signing_keys WHERE kid = ?", kid).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if at == nil {
		return time.Time{}, false
	}
	return *at, true
}

func reload(t *testing.T, ks ...*Keyring) {
	t.Helper()
	for _, k := range ks {
		if err := k.Reload(t.Context()); err != nil {
			t.Fatalf("Reload: %v", err)
		}
	}
}

// signedKid signs with k and returns the token's kid, after checking that the token verifies
// with the published key of that kid, with its alg.
func signedKid(t *testing.T, k *Keyring) string {
	t.Helper()
	tok, err := k.Sign([]byte(`{"sub":"x"}`), "at+jwt")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return verify(t, k, tok)
}

// verify checks tok against k's published set and returns its kid.
func verify(t testing.TB, k *Keyring, tok string) string {
	t.Helper()
	msg, err := jws.Parse([]byte(tok))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	h := msg.Signatures()[0].ProtectedHeaders()
	kid, _ := h.KeyID()
	pk, ok := k.Key(kid)
	if !ok {
		t.Fatalf("kid %s is not published", kid)
	}
	alg := jwa.RS256()
	if pk.Alg == AlgES256 {
		alg = jwa.ES256()
	}
	if got, _ := h.Algorithm(); got != alg {
		t.Fatalf("alg %s for a %s key", got, pk.Alg)
	}
	if _, err := jws.Verify([]byte(tok), jws.WithKey(alg, pk.Key)); err != nil {
		t.Fatalf("verify with %s: %v", kid, err)
	}
	return kid
}

func publishedKids(t *testing.T, k *Keyring) []string {
	t.Helper()
	pks, ok := k.Published()
	if !ok {
		t.Fatal("Published: not synced")
	}
	var out []string
	for _, pk := range pks {
		out = append(out, pk.Kid)
	}
	return out
}

// rotate sets up K1 signing on replica a, then edits the file as runbook 1 does, without the
// wait: K1 retired, K2 (new) active.
func rotate(t *testing.T, e *env) (a *Keyring, k1, k2 string) {
	t.Helper()
	r := rsaKeys()
	k1, k2 = kidOf(t, r[0]), kidOf(t, r[1])
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}})
	a = e.replica(t)
	e.promotable(t, k1)
	reload(t, a)
	if got := signedKid(t, a); got != k1 {
		t.Fatalf("before the rotation: signed with %s, want K1", got)
	}
	e.write(t, []spec{
		{alg: AlgRS256, state: StateRetired, key: r[0]},
		{alg: AlgRS256, state: StateActive, key: r[1]},
	})
	return a, k1, k2
}

// TestT15SecondReplica: a key set active before min_publish_before_use does not sign on a second
// replica either; the previous key keeps signing (T-15, I-14).
func TestT15SecondReplica(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, k1, k2 := rotate(t, e)
	b := e.replica(t)
	reload(t, a)
	for name, k := range map[string]*Keyring{"replica a": a, "replica b": b} {
		if got := signedKid(t, k); got != k1 {
			t.Errorf("%s signed with %s, want K1", name, got)
		}
		if got := publishedKids(t, k); len(got) != 2 || got[0] != k1 || got[1] != k2 {
			t.Errorf("%s publishes %v, want [K1 K2]", name, got)
		}
	}
	if _, ok := e.retiredAt(t, k1); ok {
		t.Error("K1 has retired_at while it still signs")
	}
	if !strings.Contains(e.logs.String(), `"msg":"signing key not promotable"`) {
		t.Errorf("no key_not_promotable log in %s", e.logs.String())
	}
}

// TestT15Restart: the same after a restart; once K2 is promotable (force-activate's effect), every
// replica signs with it and K1's retirement window starts.
func TestT15Restart(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, k1, k2 := rotate(t, e)
	reload(t, a)
	restarted := e.replica(t)
	if got := signedKid(t, restarted); got != k1 {
		t.Fatalf("after a restart: signed with %s, want K1", got)
	}

	e.promotable(t, k2)
	reload(t, a, restarted)
	for name, k := range map[string]*Keyring{"replica a": a, "restarted": restarted} {
		if got := signedKid(t, k); got != k2 {
			t.Errorf("%s signed with %s, want K2", name, got)
		}
		if got := publishedKids(t, k); len(got) != 2 {
			t.Errorf("%s publishes %v, want K1 (retired, in its window) and K2", name, got)
		}
	}
	if _, ok := e.retiredAt(t, k1); !ok {
		t.Error("K1 has no retired_at after it stopped signing")
	}
}

// TestNotPromotableNoPrevious: a new active key with no previous key in the file: nothing signs
// and readiness fails, but the key is published.
func TestNotPromotableNoPrevious(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}})
	k := e.replica(t)
	if _, err := k.Sign([]byte("{}"), "at+jwt"); !errors.Is(err, app.ErrNoSigningKey) {
		t.Errorf("Sign = %v, want ErrNoSigningKey", err)
	}
	if err := k.Ready(t.Context()); err == nil {
		t.Error("Ready = nil, want a failure")
	}
	if got := publishedKids(t, k); len(got) != 1 || got[0] != kidOf(t, r[0]) {
		t.Errorf("published %v, want the new key", got)
	}
	if !strings.Contains(e.logs.String(), `"msg":"signing key not promotable"`) {
		t.Errorf("no key_not_promotable log in %s", e.logs.String())
	}

	// The previous key is gone from the file: the same.
	e.promotable(t, kidOf(t, r[0]))
	reload(t, k)
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[1]}})
	reload(t, k)
	if err := k.Ready(t.Context()); err == nil {
		t.Error("previous key removed: Ready = nil, want a failure")
	}
}

// TestFallbackAfterRollback: K1 signs, then K2, then K1 again (a rollback); a new key set active
// without the wait falls back to K1, the key that signed last, and K1 stays published while it
// signs although K2's earlier retirement has left its window.
func TestFallbackAfterRollback(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	k1, k2, k3 := kidOf(t, r[0]), kidOf(t, r[1]), kidOf(t, r[2])
	window := (accessTTL + retiredGrace).Seconds()
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}})
	k := e.replica(t)
	e.promotable(t, k1)
	reload(t, k)

	e.write(t, []spec{{alg: AlgRS256, state: StateRetired, key: r[0]}, {alg: AlgRS256, state: StateActive, key: r[1]}})
	reload(t, k)
	e.promotable(t, k2)
	reload(t, k)
	if got := signedKid(t, k); got != k2 {
		t.Fatalf("after the rotation: signed with %s, want K2", got)
	}

	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}, {alg: AlgRS256, state: StateRetired, key: r[1]}})
	reload(t, k)
	if got := signedKid(t, k); got != k1 {
		t.Fatalf("after the rollback: signed with %s, want K1", got)
	}
	e.exec(t, "UPDATE signing_keys SET retired_at = now() - make_interval(secs => ?) WHERE kid = ?", window+60, k2)

	e.write(t, []spec{
		{alg: AlgRS256, state: StateRetired, key: r[0]},
		{alg: AlgRS256, state: StateRetired, key: r[1]},
		{alg: AlgRS256, state: StateActive, key: r[2]},
	})
	reload(t, k)
	if got := signedKid(t, k); got != k1 {
		t.Errorf("new key not promotable: signed with %s, want K1, the key that signed last", got)
	}
	if got := publishedKids(t, k); len(got) != 2 || got[0] != k1 || got[1] != k3 {
		t.Errorf("published %v, want [K1 K3]", got)
	}
}

// TestFallbackSignerPublished: the previous key keeps signing although it was retired long
// enough ago to have left the JWKS; it is published again, and its window starts only once it
// stops signing.
func TestFallbackSignerPublished(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	k1, k3 := kidOf(t, r[0]), kidOf(t, r[2])
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}})
	k := e.replica(t)
	e.promotable(t, k1)
	reload(t, k)
	e.exec(t, "UPDATE signing_keys SET retired_at = now() - interval '1 day' WHERE kid = ?", k1)

	e.write(t, []spec{{alg: AlgRS256, state: StateRetired, key: r[0]}, {alg: AlgRS256, state: StateActive, key: r[2]}})
	reload(t, k)
	if got := signedKid(t, k); got != k1 {
		t.Fatalf("signed with %s, want K1", got)
	}
	if _, ok := e.retiredAt(t, k1); ok {
		t.Error("K1 has retired_at while it still signs")
	}

	e.promotable(t, k3)
	reload(t, k)
	if got := signedKid(t, k); got != k3 {
		t.Errorf("K3 promotable: signed with %s, want K3", got)
	}
	if _, ok := k.Key(k1); !ok {
		t.Error("K1 left the JWKS as soon as it stopped signing, want its full window")
	}
}

// TestRetiredLeavesJWKS: a retired key stays published until access TTL + 5 min after its
// retirement, and not after.
func TestRetiredLeavesJWKS(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	k1, k2 := kidOf(t, r[0]), kidOf(t, r[1])
	e.write(t, []spec{
		{alg: AlgRS256, state: StateRetired, key: r[0]},
		{alg: AlgRS256, state: StateActive, key: r[1]},
	})
	k := e.replica(t)
	e.promotable(t, k2)
	window := (accessTTL + retiredGrace).Seconds()

	e.exec(t, "UPDATE signing_keys SET retired_at = now() - make_interval(secs => ?) WHERE kid = ?", window-1, k1)
	reload(t, k)
	if _, ok := k.Key(k1); !ok {
		t.Error("1 s before the end of the window: K1 not published")
	}

	e.exec(t, "UPDATE signing_keys SET retired_at = now() - make_interval(secs => ?) WHERE kid = ?", window+1, k1)
	reload(t, k)
	if _, ok := k.Key(k1); ok {
		t.Error("1 s after the end of the window: K1 still published")
	}
	if got := publishedKids(t, k); len(got) != 1 || got[0] != k2 {
		t.Errorf("published %v, want [K2]", got)
	}
}

func TestReloadInvalidKeepsPrevious(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}, {alg: AlgRS256, state: StateNext, key: r[1]}})
	k := e.replica(t)
	e.promotable(t, kidOf(t, r[0]))
	reload(t, k)

	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}, {alg: AlgRS256, state: StateActive, key: r[1]}})
	if err := k.Reload(t.Context()); err == nil {
		t.Fatal("Reload of an invalid file = nil")
	}
	if got := signedKid(t, k); got != kidOf(t, r[0]) {
		t.Errorf("signed with %s, want the previous active key", got)
	}
	if got := publishedKids(t, k); len(got) != 2 {
		t.Errorf("published %v, want the previous two keys", got)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, `"msg":"signing keyring invalid"`) || !strings.Contains(logs, e.path) ||
		!strings.Contains(logs, "2 active keys") {
		t.Errorf("logs %s: want the error naming the file and the reason", logs)
	}
	assertNoKeyMaterial(t, logs)
}

func TestNewRefusesInvalid(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.write(t, []spec{{alg: AlgRS256, state: StateNext, key: rsaKeys()[0]}})
	if _, err := New(t.Context(), e.path, e.store, Options{}); err == nil || !strings.Contains(err.Error(), "0 active keys") {
		t.Errorf("New = %v, want the validation error", err)
	}
}

// TestReloadPEMChanged: a PEM swapped behind an unchanged keyring file is reloaded.
func TestReloadPEMChanged(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0], file: "a.pem"}})
	k := e.replica(t)
	before, _ := e.su.NewSelect().Table("signing_keys").Count(t.Context())

	dir := filepath.Dir(e.path)
	writeFile(t, filepath.Join(dir, "b.pem"), pemOf(t, r[1], pkcs8))
	if err := os.Symlink("b.pem", filepath.Join(dir, "a.pem.new")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "a.pem.new"), filepath.Join(dir, "a.pem")); err != nil {
		t.Fatal(err)
	}
	reload(t, k)
	if got := publishedKids(t, k); len(got) != 1 || got[0] != kidOf(t, r[1]) {
		t.Errorf("published %v, want the swapped key", got)
	}
	if after, _ := e.su.NewSelect().Table("signing_keys").Count(t.Context()); after != before+1 {
		t.Errorf("signing_keys rows %d → %d, want the new key recorded", before, after)
	}
}

// failingStore fails every call while fail is set.
type failingStore struct {
	app.SigningKeyStore
	mu   sync.Mutex
	fail bool
}

var errStore = errors.New("database down")

func (f *failingStore) set(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fail
}

func (f *failingStore) err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errStore
	}
	return nil
}

func (f *failingStore) Publish(ctx context.Context, keys []app.SigningKeyRecord) error {
	if err := f.err(); err != nil {
		return err
	}
	return f.SigningKeyStore.Publish(ctx, keys)
}

func (f *failingStore) Activate(ctx context.Context, kid string, d time.Duration) (bool, error) {
	if err := f.err(); err != nil {
		return false, err
	}
	return f.SigningKeyStore.Activate(ctx, kid, d)
}

func TestStartWithDatabaseDown(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}})
	store := &failingStore{SigningKeyStore: e.store, fail: true}
	k := e.replicaWith(t, store, nil)
	if err := k.Ready(t.Context()); !errors.Is(err, errNotSynced) {
		t.Errorf("Ready = %v, want errNotSynced", err)
	}
	if _, ok := k.Published(); ok {
		t.Error("Published before the first sync")
	}
	if _, err := k.Sign(nil, "at+jwt"); !errors.Is(err, app.ErrNoSigningKey) {
		t.Errorf("Sign = %v, want ErrNoSigningKey", err)
	}
	if !strings.Contains(e.logs.String(), `"msg":"signing keyring sync failed"`) {
		t.Errorf("no sync failure log in %s", e.logs.String())
	}

	store.set(false)
	reload(t, k) // the first sync records the key
	if _, ok := k.Published(); !ok {
		t.Error("after the database is back: Published not synced")
	}
	e.promotable(t, kidOf(t, r[0]))
	reload(t, k)
	if err := k.Ready(t.Context()); err != nil {
		t.Errorf("after the database is back: Ready = %v", err)
	}
}

func TestSyncFailureKeepsState(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}})
	store := &failingStore{SigningKeyStore: e.store}
	k := e.replicaWith(t, store, nil)
	e.promotable(t, kidOf(t, r[0]))
	reload(t, k)

	store.set(true)
	e.write(t, []spec{{alg: AlgRS256, state: StateRetired, key: r[0]}, {alg: AlgRS256, state: StateActive, key: r[1]}})
	if err := k.Reload(t.Context()); !errors.Is(err, errStore) {
		t.Fatalf("Reload = %v, want the store's error", err)
	}
	if got := signedKid(t, k); got != kidOf(t, r[0]) {
		t.Errorf("signed with %s, want the key of the last sync", got)
	}
	if got := publishedKids(t, k); len(got) != 1 {
		t.Errorf("published %v, want the state of the last sync", got)
	}
}

func TestRunPolls(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}})
	k, err := New(t.Context(), e.path, e.store, Options{
		MinPublishBeforeUse: minPublish, AccessTTL: accessTTL, PollInterval: 10 * time.Millisecond,
		Logger: slog.New(slog.NewJSONHandler(e.logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- k.Run(ctx) }()

	// Promotable without a change to the file: the poll promotes it.
	e.promotable(t, kidOf(t, r[0]))
	deadline := time.Now().Add(5 * time.Second)
	for k.Ready(t.Context()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("not ready 5 s after the key became promotable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r[0]}, {alg: AlgES256, state: StateNext, key: ecKeys()[0]}})
	for len(publishedKids(t, k)) != 2 {
		if time.Now().After(deadline) {
			t.Fatal("the edited file was not loaded within 5 s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestJWKSKeysGauge(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()
	k1 := kidOf(t, r[0])
	e.write(t, []spec{
		{alg: AlgRS256, state: StateRetired, key: r[0]},
		{alg: AlgRS256, state: StateActive, key: r[1]},
		{alg: AlgES256, state: StateNext, key: ecKeys()[0]},
	})
	reader := sdkmetric.NewManualReader()
	k := e.replicaWith(t, e.store, sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	e.promotable(t, kidOf(t, r[1]))
	reload(t, k)
	gauge := func() map[string]float64 {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(t.Context(), &rm); err != nil {
			t.Fatal(err)
		}
		out := map[string]float64{}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				for _, dp := range m.Data.(metricdata.Gauge[float64]).DataPoints {
					st, _ := dp.Attributes.Value("state")
					out[st.AsString()] = dp.Value
				}
			}
		}
		return out
	}
	if got := gauge(); got["next"] != 1 || got["active"] != 1 || got["retired"] != 1 {
		t.Errorf("auth1_jwks_keys = %v, want 1 each", got)
	}
	e.exec(t, "UPDATE signing_keys SET retired_at = now() - interval '1 day' WHERE kid = ?", k1)
	reload(t, k)
	if got := gauge(); got["retired"] != 0 || got["active"] != 1 {
		t.Errorf("after the window: auth1_jwks_keys = %v, want retired 0", got)
	}
}

func TestSignHeader(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ec := ecKeys()[0]
	e.write(t, []spec{{alg: AlgES256, state: StateActive, key: ec}})
	k := e.replica(t)
	e.promotable(t, kidOf(t, ec))
	reload(t, k)
	tok, err := k.Sign([]byte(`{"a":1}`), "at+jwt")
	if err != nil {
		t.Fatal(err)
	}
	if kid := verify(t, k, tok); kid != kidOf(t, ec) {
		t.Errorf("kid %s, want the ES256 key", kid)
	}
	msg, _ := jws.Parse([]byte(tok))
	if typ, _ := msg.Signatures()[0].ProtectedHeaders().Type(); typ != "at+jwt" {
		t.Errorf("typ %q, want at+jwt", typ)
	}
	if string(msg.Payload()) != `{"a":1}` {
		t.Errorf("payload %q", msg.Payload())
	}
}

func TestKeyringNeverPrinted(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: rsaKeys()[0]}, {alg: AlgES256, state: StateNext, key: ecKeys()[0]}})
	k := e.replica(t)
	e.promotable(t, kidOf(t, rsaKeys()[0]))
	reload(t, k)
	for _, v := range []any{k, *k.cur.Load(), struct{ K *Keyring }{k}} {
		assertNoKeyMaterial(t, formatted(v))
	}
	assertNoKeyMaterial(t, e.logs.String())
}
