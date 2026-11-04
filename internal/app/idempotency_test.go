package app_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
)

// idemStore is a transactional fake of the unit of work, its savepoints and the key repository:
// rows claimed and stored in a Do commit when fn returns nil and are dropped otherwise.
type idemStore struct {
	committed map[string]app.StoredIdempotency
	pending   map[string]app.StoredIdempotency
	inTx      bool
	rollbacks int // savepoints rolled back
	claimErr  error
}

func newIdemStore() *idemStore {
	return &idemStore{committed: map[string]app.StoredIdempotency{}}
}

func idemKey(req app.IdempotencyRequest) string { return req.Caller + "\x00" + req.Key }

func (s *idemStore) Do(ctx context.Context, fn func(context.Context) error) error {
	s.inTx, s.pending = true, map[string]app.StoredIdempotency{}
	defer func() { s.inTx, s.pending = false, nil }()
	if err := fn(ctx); err != nil {
		return err
	}
	for k, v := range s.pending {
		s.committed[k] = v
	}
	return nil
}

func (s *idemStore) Savepoint(ctx context.Context, fn func(context.Context) error) error {
	err := fn(ctx)
	if err != nil {
		s.rollbacks++
	}
	return err
}

func (s *idemStore) Claim(_ context.Context, req app.IdempotencyRequest, ttl time.Duration) (*app.StoredIdempotency, error) {
	if !s.inTx || ttl != time.Hour {
		return nil, errors.New("claim outside a transaction or with the wrong ttl")
	}
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	if row, ok := s.committed[idemKey(req)]; ok {
		return &row, nil
	}
	s.pending[idemKey(req)] = app.StoredIdempotency{Hash: req.Hash}
	return nil, nil
}

func (s *idemStore) Store(_ context.Context, req app.IdempotencyRequest, resp app.IdempotentResponse) error {
	row, ok := s.pending[idemKey(req)]
	if !s.inTx || !ok {
		return errors.New("store without a claim")
	}
	row.Response = resp
	s.pending[idemKey(req)] = row
	return nil
}

func newIdempotency(t *testing.T, s *idemStore) *app.Idempotency {
	t.Helper()
	i, err := app.NewIdempotency(s, s, s, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

var (
	reqA           = app.IdempotencyRequest{Caller: "client:support", Key: "k-1", Hash: []byte("hash-a")}
	ok201          = app.IdempotentResponse{Status: 201, ContentType: "application/json", Body: []byte(`{"n":1}`)}
	statusConflict = &domain.Error{Code: domain.CodeStatusTransitionInvalid}
)

// call counts op and render calls; render answers by err with status.
type call struct {
	ops, renders int
	opErr        error
	status       int // the status render gives an error
	body         []byte
	fixed        *app.IdempotentResponse // when set, what render always gives
}

func (c *call) op(context.Context) error { c.ops++; return c.opErr }

func (c *call) render(err error) app.IdempotentResponse {
	c.renders++
	if c.fixed != nil {
		return *c.fixed
	}
	if err != nil {
		return app.IdempotentResponse{Status: c.status, ContentType: "application/problem+json", Body: []byte(`{"code":"x"}`)}
	}
	if c.body != nil {
		return app.IdempotentResponse{Status: 201, ContentType: "application/json", Body: c.body}
	}
	return ok201
}

func TestRunStoresAndReplays(t *testing.T) {
	t.Parallel()
	s := newIdemStore()
	i := newIdempotency(t, s)

	first := &call{}
	got, err := i.Run(t.Context(), reqA, first.op, first.render)
	if err != nil || !cmp.Equal(ok201, got) || first.ops != 1 || first.renders != 1 {
		t.Fatalf("first Run = %v, %v; op %d, render %d calls", got, err, first.ops, first.renders)
	}
	if row := s.committed[idemKey(reqA)]; !cmp.Equal(ok201, row.Response) {
		t.Errorf("committed %v, want the response", row)
	}

	again := &call{}
	got, err = i.Run(t.Context(), reqA, again.op, again.render)
	if err != nil || !cmp.Equal(ok201, got) {
		t.Errorf("replay = %v, %v; want the stored response", got, err)
	}
	if again.ops != 0 || again.renders != 0 {
		t.Errorf("replay ran op %d and render %d times, want neither", again.ops, again.renders)
	}
}

func TestRunReused(t *testing.T) {
	t.Parallel()
	s := newIdemStore()
	i := newIdempotency(t, s)
	if _, err := i.Run(t.Context(), reqA, (&call{}).op, (&call{}).render); err != nil {
		t.Fatal(err)
	}
	other := reqA
	other.Hash = []byte("hash-b")
	c := &call{}
	_, err := i.Run(t.Context(), other, c.op, c.render)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeIdempotencyKeyReused {
		t.Errorf("Run with another hash = %v, want IDEMPOTENCY_KEY_REUSED", err)
	}
	if c.ops != 0 || c.renders != 0 {
		t.Error("the reused request ran")
	}
	if row := s.committed[idemKey(reqA)]; !bytes.Equal(row.Hash, reqA.Hash) {
		t.Error("the reused request changed the stored row")
	}
}

// TestRunStoresClientError: a 4xx rolls the operation back to its savepoint, is stored and
// committed, and replays.
func TestRunStoresClientError(t *testing.T) {
	t.Parallel()
	s := newIdemStore()
	i := newIdempotency(t, s)
	c := &call{opErr: statusConflict, status: 409}
	got, err := i.Run(t.Context(), reqA, c.op, c.render)
	if err != nil || got.Status != 409 {
		t.Fatalf("Run = %v, %v; want the 409 response and no error", got, err)
	}
	if s.rollbacks != 1 {
		t.Errorf("savepoint rollbacks = %d, want 1", s.rollbacks)
	}
	if row, ok := s.committed[idemKey(reqA)]; !ok || row.Response.Status != 409 {
		t.Errorf("committed %v, %v; want the 409", row, ok)
	}
	again := &call{}
	if got, err := i.Run(t.Context(), reqA, again.op, again.render); err != nil || got.Status != 409 || again.ops != 0 {
		t.Errorf("replay = %v, %v, op ran %d times; want the 409 replayed", got, err, again.ops)
	}
}

// TestRunLeavesKeyFree: a 5xx, a 429, an oversized body or a status out of range commits
// nothing, so a retry runs the operation.
func TestRunLeavesKeyFree(t *testing.T) {
	t.Parallel()
	boom := errors.New("database gone")
	limited := &domain.Error{Code: domain.CodeRateLimited, RetryAfter: time.Second}
	for _, tc := range []struct {
		name    string
		c       *call
		wantErr error
	}{
		{"server error", &call{opErr: boom, status: 503}, boom},
		{"rate limited", &call{opErr: limited, status: 429}, limited},
		{"rendered 500 without an error", &call{fixed: &app.IdempotentResponse{Status: 500}}, nil},
		{"status below 200", &call{fixed: &app.IdempotentResponse{Status: 101}}, nil},
		{"oversized body", &call{body: []byte(strings.Repeat("x", 64<<10+1))}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newIdemStore()
			i := newIdempotency(t, s)
			_, err := i.Run(t.Context(), reqA, tc.c.op, tc.c.render)
			if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
				t.Fatalf("Run = %v, want %v", err, tc.wantErr)
			}
			if len(s.committed) != 0 {
				t.Errorf("committed %v, want nothing", s.committed)
			}
			retry := &call{}
			if _, err := i.Run(t.Context(), reqA, retry.op, retry.render); err != nil || retry.ops != 1 {
				t.Errorf("retry = %v, op ran %d times; want it to run", err, retry.ops)
			}
		})
	}
}

func TestRunClaimError(t *testing.T) {
	t.Parallel()
	s := newIdemStore()
	s.claimErr = &domain.Error{Code: domain.CodeUnavailable, RetryAfter: time.Second}
	c := &call{}
	_, err := newIdempotency(t, s).Run(t.Context(), reqA, c.op, c.render)
	if !errors.Is(err, s.claimErr) || c.ops != 0 {
		t.Errorf("Run = %v, op ran %d times; want the claim's error and no op", err, c.ops)
	}
}

func TestNewIdempotencyRefuses(t *testing.T) {
	t.Parallel()
	s := newIdemStore()
	for name, f := range map[string]func() (*app.Idempotency, error){
		"no unit of work": func() (*app.Idempotency, error) { return app.NewIdempotency(nil, s, s, time.Hour) },
		"no savepoints":   func() (*app.Idempotency, error) { return app.NewIdempotency(s, nil, s, time.Hour) },
		"no keys":         func() (*app.Idempotency, error) { return app.NewIdempotency(s, s, nil, time.Hour) },
		"no ttl":          func() (*app.Idempotency, error) { return app.NewIdempotency(s, s, s, 0) },
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
