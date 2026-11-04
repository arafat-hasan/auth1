package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
)

var _ app.IdempotencyKeys = (*postgres.IdempotencyKeys)(nil)

const day = 24 * time.Hour

// keysEnv is accountsEnv with the idempotency key repository.
type keysEnv struct {
	*accountsEnv
	keys *postgres.IdempotencyKeys
}

func keysDB(t *testing.T) *keysEnv {
	t.Helper()
	e := accountsDB(t)
	return &keysEnv{accountsEnv: e, keys: postgres.NewIdempotencyKeys(e.app, e.fc)}
}

func idemRequest(caller, key, body string) app.IdempotencyRequest {
	h := sha256.Sum256([]byte(body))
	return app.IdempotencyRequest{Caller: caller, Key: key, Hash: h[:]}
}

var created = app.IdempotentResponse{Status: 201, ContentType: "application/json", Body: []byte(`{"display_name":"Ada Lovelace"}`)}

// claim runs Claim in its own transaction and commits.
func (e *keysEnv) claim(t *testing.T, req app.IdempotencyRequest) *app.StoredIdempotency {
	t.Helper()
	var got *app.StoredIdempotency
	e.do(t, func(ctx context.Context) error {
		var err error
		got, err = e.keys.Claim(ctx, req, day)
		return err
	})
	return got
}

// store claims req's key and stores resp, in one transaction.
func (e *keysEnv) store(t *testing.T, req app.IdempotencyRequest, resp app.IdempotentResponse) {
	t.Helper()
	e.do(t, func(ctx context.Context) error {
		got, err := e.keys.Claim(ctx, req, day)
		if err != nil {
			return err
		}
		if got != nil {
			t.Fatalf("Claim of a fresh key = %v, want nil", got)
		}
		return e.keys.Store(ctx, req, resp)
	})
}

func TestIdempotencyClaimAndStore(t *testing.T) {
	t.Parallel()
	e := keysDB(t)
	req := idemRequest("client:support", "k-1", "a")
	e.store(t, req, created)

	got := e.claim(t, idemRequest("client:support", "k-1", "b"))
	if got == nil {
		t.Fatal("Claim of a stored key = nil, want its row")
	}
	if !bytes.Equal(got.Hash, req.Hash) {
		t.Errorf("hash = %x, want the first request's %x", got.Hash, req.Hash)
	}
	if diff := cmp.Diff(created, got.Response); diff != "" {
		t.Errorf("response (-want +got):\n%s", diff)
	}

	// The key belongs to its caller.
	if got := e.claim(t, idemRequest("workload:spiffe://a", "k-1", "a")); got != nil {
		t.Errorf("another caller's Claim = %v, want nil", got)
	}
	empty := app.IdempotentResponse{Status: 204}
	e.store(t, idemRequest("client:support", "k-2", "a"), empty)
	if got := e.claim(t, idemRequest("client:support", "k-2", "a")); got == nil || !cmp.Equal(empty, got.Response) {
		t.Errorf("204 replay = %v, want %v", got, empty)
	}
}

// TestIdempotencyResponseSealed: the stored response is not plaintext, and opens only in its own
// row (TDD-01 §3).
func TestIdempotencyResponseSealed(t *testing.T) {
	t.Parallel()
	e := keysDB(t)
	e.store(t, idemRequest("client:support", "k-1", "a"), created)
	e.store(t, idemRequest("client:support", "k-2", "a"), app.IdempotentResponse{Status: 204})

	var status int
	var raw []byte
	if err := e.su.QueryRowContext(t.Context(), "SELECT status, response FROM idempotency_keys WHERE key = 'k-1'").
		Scan(&status, &raw); err != nil {
		t.Fatal(err)
	}
	if status != 201 || bytes.Contains(raw, []byte("Ada")) || bytes.Contains(raw, []byte("application/json")) {
		t.Errorf("stored status %d, response %q: want 201 and a sealed response", status, raw)
	}

	e.exec(t, "UPDATE idempotency_keys SET response = ? WHERE key = 'k-2'", raw)
	err := e.uow.Do(t.Context(), func(ctx context.Context) error {
		_, err := e.keys.Claim(ctx, idemRequest("client:support", "k-2", "a"), day)
		return err
	})
	if !errors.Is(err, app.ErrCiphertextInvalid) {
		t.Errorf("Claim of a response moved from another row = %v, want ErrCiphertextInvalid", err)
	}
}

// TestIdempotencyExpiredReclaimed: a row older than the ttl counts as absent.
func TestIdempotencyExpiredReclaimed(t *testing.T) {
	t.Parallel()
	e := keysDB(t)
	e.store(t, idemRequest("client:support", "k-1", "a"), created)
	e.exec(t, "UPDATE idempotency_keys SET created_at = now() - interval '23 hours'")
	if got := e.claim(t, idemRequest("client:support", "k-1", "b")); got == nil {
		t.Fatal("a row younger than the ttl was reclaimed")
	}
	e.exec(t, "UPDATE idempotency_keys SET created_at = now() - interval '25 hours'")

	req := idemRequest("client:support", "k-1", "b")
	e.store(t, req, app.IdempotentResponse{Status: 204})
	got := e.claim(t, req)
	if got == nil || !bytes.Equal(got.Hash, req.Hash) || got.Response.Status != 204 {
		t.Errorf("after reclaiming: %v, want the new request's row", got)
	}
}

// holdKey claims req in a transaction of its own and keeps it open until release is closed; then
// it stores resp and commits, or rolls back when resp is nil. claimed is closed once it holds the
// key.
func (e *keysEnv) holdKey(t *testing.T, req app.IdempotencyRequest, resp *app.IdempotentResponse) (claimed, release chan struct{}, done chan error) {
	t.Helper()
	claimed, release, done = make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- e.uow.Do(context.Background(), func(ctx context.Context) error {
			if _, err := e.keys.Claim(ctx, req, day); err != nil {
				close(claimed)
				return err
			}
			close(claimed)
			<-release
			if resp == nil {
				return errSentinel
			}
			return e.keys.Store(ctx, req, *resp)
		})
	}()
	return claimed, release, done
}

// TestIdempotencyClaimWaits: a Claim of a key another transaction holds waits for it. When the
// holder commits, it returns the holder's row; when the holder rolls back, the key is free.
func TestIdempotencyClaimWaits(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		resp *app.IdempotentResponse
	}{{"holder commits", &created}, {"holder rolls back", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := keysDB(t)
			req := idemRequest("client:support", "k-1", "a")
			claimed, release, done := e.holdKey(t, req, tc.resp)
			<-claimed

			type result struct {
				got *app.StoredIdempotency
				err error
			}
			second := make(chan result, 1)
			go func() {
				var r result
				r.err = e.uow.Do(context.Background(), func(ctx context.Context) error {
					var err error
					r.got, err = e.keys.Claim(ctx, req, day)
					return err
				})
				second <- r
			}()
			select {
			case r := <-second:
				t.Fatalf("the second Claim returned %v, %v while the key was held", r.got, r.err)
			case <-time.After(300 * time.Millisecond):
			}
			close(release)
			if err := <-done; err != nil && tc.resp != nil {
				t.Fatalf("holder: %v", err)
			}
			r := <-second
			if r.err != nil {
				t.Fatalf("second Claim: %v", r.err)
			}
			switch {
			case tc.resp != nil && (r.got == nil || !cmp.Equal(created, r.got.Response)):
				t.Errorf("second Claim = %v, want the holder's response", r.got)
			case tc.resp == nil && r.got != nil:
				t.Errorf("second Claim = %v, want the key free", r.got)
			}
		})
	}
}

// TestIdempotencyClaimTimeout: a wait past 5 s is UNAVAILABLE with a retry hint.
func TestIdempotencyClaimTimeout(t *testing.T) {
	t.Parallel()
	e := keysDB(t)
	req := idemRequest("client:support", "k-1", "a")
	claimed, release, done := e.holdKey(t, req, nil)
	<-claimed
	defer func() { close(release); <-done }()

	start := time.Now()
	err := e.uow.Do(t.Context(), func(ctx context.Context) error {
		_, err := e.keys.Claim(ctx, req, day)
		return err
	})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeUnavailable || de.RetryAfter != time.Second {
		t.Errorf("Claim of a held key = %v, want UNAVAILABLE with RetryAfter 1s", err)
	}
	if waited := time.Since(start); waited < 4*time.Second || waited > 10*time.Second {
		t.Errorf("waited %v, want about 5s", waited)
	}
}

func TestIdempotencyNoTransaction(t *testing.T) {
	t.Parallel()
	e := keysDB(t)
	req := idemRequest("client:support", "k-1", "a")
	if _, err := e.keys.Claim(t.Context(), req, day); !errors.Is(err, postgres.ErrNoTransaction) {
		t.Errorf("Claim outside Do = %v, want ErrNoTransaction", err)
	}
	if err := e.keys.Store(t.Context(), req, created); !errors.Is(err, postgres.ErrNoTransaction) {
		t.Errorf("Store outside Do = %v, want ErrNoTransaction", err)
	}
}
