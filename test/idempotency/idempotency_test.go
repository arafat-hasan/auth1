package idempotency_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/http/middleware"
	"github.com/arafat-hasan/auth1/internal/http/middleware/caller"
	"github.com/arafat-hasan/auth1/internal/http/middleware/idempotency"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

// callerHeader names the test caller; the real caller.Resolver is not mounted.
const callerHeader = "X-Test-Caller"

// env is the component on a migrated database: the API with the test-only handler, and a
// superuser pool for reading rows.
type env struct {
	api     http.Handler
	su      *bun.DB
	account uuid.UUID
}

// open opens a pool of maxConns on dsn.
func open(t *testing.T, dsn string, maxConns int) *bun.DB {
	t.Helper()
	file := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(file, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := postgres.Open(config.Database{DSNFile: config.NewSecretFile(file), MaxConns: maxConns, AcquireTimeout: 5 * time.Second},
		config.EnvDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func randomKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, crypto.KeySize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dsn := pgtest.DSN(t)
	su := open(t, dsn, 2)
	// The handler's effect, in a table of its own: one row per run of the operation.
	for _, q := range []string{
		"CREATE TABLE idem_effects (seq serial PRIMARY KEY, key text NOT NULL)",
		"GRANT SELECT, INSERT ON idem_effects TO auth1_app",
		"GRANT USAGE ON SEQUENCE idem_effects_seq_seq TO auth1_app",
	} {
		if _, err := su.ExecContext(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	db := open(t, pgtest.As(t, dsn, pgtest.App), 16)

	ring, err := crypto.ParseKeyring(fmt.Appendf(nil, "keys:\n  - {id: 1, key: %q, state: active}\n", randomKey(t)), crypto.StateDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.ParseKey([]byte(randomKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	bidx, err := crypto.NewBlindIndex(key)
	if err != nil {
		t.Fatal(err)
	}
	fc := crypto.NewFieldCrypto(ring)
	uow := postgres.NewUnitOfWork(db, 5*time.Second, noop.NewTracerProvider())
	accounts := postgres.NewAccounts(db, fc, bidx)
	idem, err := app.NewIdempotency(uow, uow, postgres.NewIdempotencyKeys(db, fc), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	id := uuid.Must(uuid.NewV7())
	if err := uow.Do(t.Context(), func(ctx context.Context) error {
		return accounts.Create(ctx, account.NewAccount{
			ID: id, DisplayName: "Ada Lovelace", Locale: "en-GB", RegisteredVia: "web",
			Password: account.PasswordCredential{Hash: "$argon2id$v=19$m=65536,t=2,p=1$c2FsdA$aGFzaA", PepperKID: "3"},
			Roles:    []string{"member"}, GrantedBy: "system",
		})
	}); err != nil {
		t.Fatal(err)
	}

	pw := problem.New(slog.New(slog.DiscardHandler))
	h := &things{uow: uow, accounts: accounts, idem: idem, db: db, pw: pw}
	r := chi.NewRouter()
	r.Use(middleware.BodyLimit(64<<10, pw))
	mw, err := idempotency.New(idempotency.Options{
		Match:    func(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/things/") },
		Problems: pw,
		Caller: func(ctx context.Context) (caller.Caller, bool) {
			c, ok := ctx.Value(callerKey{}).(caller.Caller)
			return c, ok
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Use(mw)
	r.Post("/things/{name}", h.ServeHTTP)
	api := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if id := req.Header.Get(callerHeader); id != "" {
			req = req.WithContext(context.WithValue(req.Context(), callerKey{}, caller.Caller{Kind: caller.KindClient, ID: id}))
		}
		r.ServeHTTP(w, req)
	})
	return &env{api: api, su: su, account: id}
}

type callerKey struct{}

// things is the test-only operation, a use case and its handler in one: it locks the account,
// records an effect, and answers 201 with the effect's sequence number. The body's "fail" makes it
// refuse with 409 after its writes ("conflict"), fail with an unexpected error ("crash"), or
// answer a body over the stored limit ("big").
type things struct {
	uow      app.UnitOfWork
	accounts *postgres.Accounts
	idem     *app.Idempotency
	db       *bun.DB
	pw       *problem.Writer
}

func (h *things) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, _ := idempotency.From(r.Context())
	var in struct {
		Account uuid.UUID `json:"account"`
		Fail    string    `json:"fail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		h.pw.WriteBindError(w, r, err)
		return
	}
	var seq int
	op := func(ctx context.Context) error {
		return h.uow.Do(ctx, func(ctx context.Context) error { // the use case's own Do joins Run's
			if _, err := h.accounts.GetForUpdate(ctx, in.Account); err != nil {
				return err
			}
			if err := postgres.Conn(ctx, h.db).QueryRowContext(ctx,
				"INSERT INTO idem_effects (key) VALUES (?) RETURNING seq", req.Key).Scan(&seq); err != nil {
				return err
			}
			switch in.Fail {
			case "conflict":
				return &domain.Error{Code: domain.CodeStatusTransitionInvalid, Detail: "Not from this status."}
			case "crash":
				return errors.New("the operation crashed")
			}
			return nil
		})
	}
	render := func(err error) (app.IdempotentResponse, error) {
		if err != nil {
			return idempotency.RenderError(h.pw, r, err)
		}
		return idempotency.Render(func(w http.ResponseWriter) error {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			pad := ""
			if in.Fail == "big" {
				pad = strings.Repeat("x", app.MaxStoredBody)
			}
			return json.NewEncoder(w).Encode(map[string]any{"name": chi.URLParam(r, "name"), "seq": seq, "pad": pad})
		})
	}
	resp, err := h.idem.Run(r.Context(), req, op, render)
	if err != nil {
		h.pw.Write(w, r, err)
		return
	}
	_ = idempotency.Write(w, resp)
}

// answer is one exchange's response.
type answer struct {
	Status int
	Header http.Header
	Body   string
}

// post sends POST /things/<name> as caller with key and body.
func (e *env) post(t *testing.T, caller, name, key, body string) answer {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/things/"+name, strings.NewReader(body))
	req.Header.Set(callerHeader, caller)
	req.Header.Set("Idempotency-Key", key)
	rec := httptest.NewRecorder()
	e.api.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Result().Body)
	return answer{Status: rec.Code, Header: rec.Header(), Body: string(b)}
}

func (e *env) body(extra string) string {
	return fmt.Sprintf(`{"account":%q%s}`, e.account, extra)
}

// effects counts the operation's effect rows for key.
func (e *env) effects(t *testing.T, key string) int {
	t.Helper()
	var n int
	if err := e.su.QueryRowContext(t.Context(), "SELECT count(*) FROM idem_effects WHERE key = ?", key).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// row reads the key's stored status, or 0 when there is no row.
func (e *env) row(t *testing.T, caller, key string) int {
	t.Helper()
	var status *int
	err := e.su.QueryRowContext(t.Context(), "SELECT status FROM idempotency_keys WHERE caller = ? AND key = ?",
		caller, key).Scan(&status)
	if err != nil || status == nil {
		return 0
	}
	return *status
}

func (e *env) version(t *testing.T) int64 {
	t.Helper()
	var v int64
	if err := e.su.QueryRowContext(t.Context(), "SELECT version FROM accounts WHERE id = ?", e.account).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func code(body string) string {
	var p struct{ Code string }
	_ = json.Unmarshal([]byte(body), &p)
	return p.Code
}

// TestT26Replay: a retry with the same key and body replays the first response, status, content
// type and body, and the operation applied once (T-26, I-9).
func TestT26Replay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	first := e.post(t, "support", "a", "k-1", e.body(`,"fail":""`))
	if first.Status != http.StatusCreated {
		t.Fatalf("first: %+v", first)
	}
	// The same request, its members reordered and spaced: the hash is of the canonical JSON.
	retry := e.post(t, "support", "a", "k-1", fmt.Sprintf(`{ "fail": "", "account": %q }`, e.account))
	if retry.Status != first.Status || retry.Body != first.Body ||
		retry.Header.Get("Content-Type") != first.Header.Get("Content-Type") {
		t.Errorf("retry %+v, want the first response %+v", retry, first)
	}
	if n := e.effects(t, "k-1"); n != 1 {
		t.Errorf("%d effects, want 1", n)
	}
	if s := e.row(t, "client:support", "k-1"); s != http.StatusCreated {
		t.Errorf("stored status %d, want 201", s)
	}
	t.Logf("first:  %d %s", first.Status, first.Body)
	t.Logf("replay: %d %s", retry.Status, retry.Body)
}

// TestT26Reused: the same key with another body, or another path, is IDEMPOTENCY_KEY_REUSED and
// applies nothing; another caller's same key is its own (T-26).
func TestT26Reused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	first := e.post(t, "support", "a", "k-1", e.body(""))
	if first.Status != http.StatusCreated {
		t.Fatalf("first: %+v", first)
	}
	for _, tc := range []struct{ name, path, body string }{
		{"another body", "a", e.body(`,"fail":"x"`)},
		{"another path", "b", e.body("")},
	} {
		got := e.post(t, "support", tc.path, "k-1", tc.body)
		if got.Status != http.StatusUnprocessableEntity || code(got.Body) != "IDEMPOTENCY_KEY_REUSED" {
			t.Errorf("%s: %+v, want 422 IDEMPOTENCY_KEY_REUSED", tc.name, got)
		}
		t.Logf("%s: %d %s", tc.name, got.Status, got.Body)
	}
	if n := e.effects(t, "k-1"); n != 1 {
		t.Errorf("%d effects, want 1", n)
	}

	other := e.post(t, "reports", "b", "k-1", e.body(""))
	if other.Status != http.StatusCreated || other.Body == first.Body {
		t.Errorf("another caller: %+v, want its own 201", other)
	}
}

// TestConcurrentApplyOnce: concurrent requests with one key apply once; the others wait for the
// first and replay it.
func TestConcurrentApplyOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	const n = 10
	answers := make([]answer, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { answers[i] = e.post(t, "support", "a", "k-1", e.body("")) })
	}
	wg.Wait()
	for i, a := range answers {
		if a.Status != http.StatusCreated || a.Body != answers[0].Body {
			t.Errorf("answer %d: %+v, want %+v", i, a, answers[0])
		}
	}
	if got := e.effects(t, "k-1"); got != 1 {
		t.Errorf("%d effects, want 1", got)
	}
}

// TestServerErrorLeavesKeyFree: a 5xx rolls back the effect and stores no key, so a retry runs.
func TestServerErrorLeavesKeyFree(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, fail := range []string{"crash", "big"} {
		key := "k-" + fail
		got := e.post(t, "support", "a", key, e.body(`,"fail":"`+fail+`"`))
		if got.Status < 500 {
			t.Errorf("%s: %+v, want a 5xx", fail, got)
		}
		if n, s := e.effects(t, key), e.row(t, "client:support", key); n != 0 || s != 0 {
			t.Errorf("%s: %d effects and stored status %d, want neither (I-9)", fail, n, s)
		}
		v := e.version(t)
		if retry := e.post(t, "support", "a", key, e.body("")); retry.Status != http.StatusCreated {
			t.Errorf("%s: retry %+v, want 201", fail, retry)
		}
		if n := e.effects(t, key); n != 1 || e.version(t) != v+1 {
			t.Errorf("%s: after the retry %d effects, version %d; want 1 and %d", fail, n, e.version(t), v+1)
		}
	}
}

// TestClientErrorStoredWithoutEffects: a 4xx is stored and replayed, and its operation's writes,
// and the version change of the account it locked, are rolled back.
func TestClientErrorStoredWithoutEffects(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.version(t)
	first := e.post(t, "support", "a", "k-1", e.body(`,"fail":"conflict"`))
	if first.Status != http.StatusConflict || code(first.Body) != "STATUS_TRANSITION_INVALID" {
		t.Fatalf("first: %+v", first)
	}
	if n := e.effects(t, "k-1"); n != 0 {
		t.Errorf("%d effects, want 0", n)
	}
	if got := e.version(t); got != v {
		t.Errorf("version %d, want %d: the refused operation moved it", got, v)
	}
	if s := e.row(t, "client:support", "k-1"); s != http.StatusConflict {
		t.Errorf("stored status %d, want 409", s)
	}
	retry := e.post(t, "support", "a", "k-1", e.body(`,"fail":"conflict"`))
	if !bytes.Equal([]byte(retry.Body), []byte(first.Body)) || retry.Status != first.Status {
		t.Errorf("retry %+v, want the stored 409 %+v", retry, first)
	}
	if n := e.effects(t, "k-1"); n != 0 {
		t.Errorf("the replay ran the operation: %d effects", n)
	}
}
