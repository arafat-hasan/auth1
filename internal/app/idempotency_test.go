package app_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	committed   map[string]app.StoredIdempotency
	pending     map[string]app.StoredIdempotency
	inTx        bool
	rollbacks   int   // savepoints rolled back
	claims      int   // Claim calls
	claimErr    error // what Claim returns
	rollbackErr error // when set, a savepoint whose fn fails cannot roll back
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
	if err != nil && s.rollbackErr != nil {
		return errors.Join(err, s.rollbackErr)
	}
	if err != nil {
		s.rollbacks++
	}
	return err
}

func (s *idemStore) Claim(_ context.Context, req app.IdempotencyRequest, ttl time.Duration) (*app.StoredIdempotency, error) {
	if !s.inTx || ttl != time.Hour {
		return nil, errors.New("claim outside a transaction or with the wrong ttl")
	}
	s.claims++
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
	reqA           = app.IdempotencyRequest{Caller: "client:support", Key: "k-1", Hash: hashOf("a")}
	ok201          = app.IdempotentResponse{Status: 201, ContentType: "application/json", Body: []byte(`{"n":1}`)}
	statusConflict = &domain.Error{Code: domain.CodeStatusTransitionInvalid}
)

func hashOf(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// call counts op and render calls; render answers by err with status.
type call struct {
	ops, renders int
	opErr        error
	status       int // the status render gives an error
	body         []byte
	fixed        *app.IdempotentResponse // when set, what render always gives
	renderErr    error                   // what render returns beside the response
}

func (c *call) op(context.Context) error { c.ops++; return c.opErr }

func (c *call) render(err error) (app.IdempotentResponse, error) {
	c.renders++
	if c.fixed != nil {
		return *c.fixed, c.renderErr
	}
	if err != nil {
		return app.IdempotentResponse{Status: c.status, ContentType: "application/problem+json", Body: []byte(`{"code":"x"}`)}, c.renderErr
	}
	if c.body != nil {
		return app.IdempotentResponse{Status: 201, ContentType: "application/json", Body: c.body}, c.renderErr
	}
	return ok201, c.renderErr
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
	other.Hash = hashOf("b")
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
		{"a refusal rendered for a success", &call{fixed: &app.IdempotentResponse{Status: 409}}, nil},
		{"a redirect rendered for a success", &call{fixed: &app.IdempotentResponse{Status: 302}}, nil},
		{"a success rendered for a refusal", &call{opErr: statusConflict, fixed: &ok201}, statusConflict},
		{"a render that failed", &call{fixed: &app.IdempotentResponse{Status: 500}, renderErr: errRender}, errRender},
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

var errRender = errors.New("encode the response")

// TestRunRollbackFailed: a savepoint that cannot roll back is a fault, not the refusal op
// returned; nothing is rendered or stored.
func TestRunRollbackFailed(t *testing.T) {
	t.Parallel()
	s := newIdemStore()
	s.rollbackErr = fmt.Errorf("roll back: %w", app.ErrSavepointRollback)
	c := &call{opErr: statusConflict, status: 409}
	_, err := newIdempotency(t, s).Run(t.Context(), reqA, c.op, c.render)
	if !errors.Is(err, app.ErrSavepointRollback) || c.renders != 0 || len(s.committed) != 0 {
		t.Errorf("Run = %v, render ran %d times, committed %v; want ErrSavepointRollback, no render, nothing stored",
			err, c.renders, s.committed)
	}
}

// TestRunRefusesIncompleteRequest: a request without its caller, key or hash, as a handler that
// did not get it from the middleware would pass, claims nothing.
func TestRunRefusesIncompleteRequest(t *testing.T) {
	t.Parallel()
	for name, req := range map[string]app.IdempotencyRequest{
		"zero":       {},
		"no caller":  {Key: "k-1", Hash: hashOf("a")},
		"no key":     {Caller: "client:support", Hash: hashOf("a")},
		"short hash": {Caller: "client:support", Key: "k-1", Hash: []byte("a")},
	} {
		s := newIdemStore()
		c := &call{}
		if _, err := newIdempotency(t, s).Run(t.Context(), req, c.op, c.render); err == nil || s.claims != 0 || c.ops != 0 {
			t.Errorf("%s: Run = %v, %d claims, op ran %d times; want an error and nothing run", name, err, s.claims, c.ops)
		}
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

// TestIdempotencyTypesRedacted: the request never shows its key, and a response, alone or in a
// stored row, never shows its body: not under fmt, slog's text or JSON handler, or json.Marshal.
func TestIdempotencyTypesRedacted(t *testing.T) {
	t.Parallel()
	req := app.IdempotencyRequest{Caller: "client:support", Key: "key-sekrit", Hash: hashOf("a")}
	resp := app.IdempotentResponse{Status: 201, ContentType: "application/json", Body: []byte(`{"name":"Ada sekrit"}`)}
	stored := app.StoredIdempotency{Hash: hashOf("a"), Response: resp}
	for name, v := range map[string]any{"request": req, "response": resp, "stored": stored} {
		var text, js bytes.Buffer
		slog.New(slog.NewTextHandler(&text, nil)).Info("x", "v", v)
		slog.New(slog.NewJSONHandler(&js, nil)).Info("x", "v", v)
		nested, err := json.Marshal(struct{ V any }{v})
		if err != nil {
			t.Fatalf("%s: json.Marshal: %v", name, err)
		}
		for _, out := range []string{fmt.Sprint(v), fmt.Sprintf("%#v", v), fmt.Sprintf("%+v", v), text.String(), js.String(), string(nested)} {
			if strings.Contains(out, "sekrit") || strings.Contains(out, base64.StdEncoding.EncodeToString(resp.Body)[:8]) {
				t.Errorf("%s: %q holds the key or body", name, out)
			}
		}
	}
}
