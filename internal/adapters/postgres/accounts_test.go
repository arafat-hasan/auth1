package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

var _ app.Accounts = (*postgres.Accounts)(nil)

// accountsEnv is the accounts repository on a migrated database, used as auth1_app, with its unit
// of work and crypto, and a superuser pool on the same database for reading and planting raw rows.
type accountsEnv struct {
	repo *postgres.Accounts
	uow  *postgres.UnitOfWork
	app  *bun.DB
	su   *bun.DB
	fc   app.FieldCrypto
	bidx app.BlindIndex
	ids  *fakes.IDs
	dsn  string // the superuser's
}

// randomKey is the base64 of 32 random bytes.
func randomKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, crypto.KeySize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// testCrypto returns field encryption and a blind index under fresh random keys.
func testCrypto(t *testing.T) (*crypto.FieldCrypto, *crypto.BlindIndex) {
	t.Helper()
	ring, err := crypto.ParseKeyring(
		fmt.Appendf(nil, "keys:\n  - {id: 1, key: %q, state: active}\n", randomKey(t)), crypto.StateDecrypt)
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
	return crypto.NewFieldCrypto(ring), bidx
}

// accountsDB returns a fresh environment. When the test ends, before the pools close, it checks
// I-17 on the database, so every test's fixtures are checked.
func accountsDB(t *testing.T) *accountsEnv {
	t.Helper()
	return accountsDBWith(t, nil)
}

// accountsDBWith is accountsDB with wrap applied to the field encryption the repository uses.
func accountsDBWith(t *testing.T, wrap func(app.FieldCrypto) app.FieldCrypto) *accountsEnv {
	t.Helper()
	dsn := pgtest.DSN(t)
	open := func(dsn string, maxConns int) *bun.DB {
		cfg := dbConfig(dsnFile(t, dsn))
		cfg.MaxConns = maxConns
		db, err := postgres.Open(cfg, config.EnvDevelopment)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	appDB, su := open(pgtest.As(t, dsn, pgtest.App), 12), open(dsn, 2)
	fc, bidx := testCrypto(t)
	var repoFC app.FieldCrypto = fc
	if wrap != nil {
		repoFC = wrap(fc)
	}
	t.Cleanup(func() { checkI17(t, su) })
	return &accountsEnv{
		repo: postgres.NewAccounts(appDB, repoFC, bidx),
		uow:  postgres.NewUnitOfWork(appDB, 5*time.Second, noop.NewTracerProvider()),
		app:  appDB, su: su, fc: fc, bidx: bidx, ids: fakes.NewIDs(), dsn: dsn,
	}
}

// checkI17 fails the test when an account that is not pending or deleted has no password (I-17).
func checkI17(t *testing.T, db *bun.DB) {
	t.Helper()
	if ids := accountsWithoutPassword(t, db); len(ids) > 0 {
		t.Errorf("I-17: accounts %v are neither pending nor deleted and have no password", ids)
	}
}

// accountsWithoutPassword returns the accounts that break I-17.
func accountsWithoutPassword(t *testing.T, db *bun.DB) []uuid.UUID {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `
		SELECT a.id FROM accounts a
		WHERE a.status NOT IN ('pending', 'deleted')
		  AND NOT EXISTS (SELECT 1 FROM password_credentials p WHERE p.account_id = a.id)
		ORDER BY a.id`)
	if err != nil {
		t.Fatalf("I-17 check: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("I-17 check: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("I-17 check: %v", err)
	}
	return ids
}

// do runs fn in one transaction and fails the test on an error.
func (e *accountsEnv) do(t *testing.T, fn func(ctx context.Context) error) {
	t.Helper()
	if err := e.uow.Do(t.Context(), fn); err != nil {
		t.Fatal(err)
	}
}

// newAccount is a pending account with a phone and an email, a password and a role.
func (e *accountsEnv) newAccount(phone, email string) account.NewAccount {
	a := account.NewAccount{
		ID: e.ids.New(), DisplayName: "Ada Lovelace", Locale: "en-GB", RegisteredVia: "web",
		Password: account.PasswordCredential{Hash: "$argon2id$v=19$m=65536,t=2,p=1$c2FsdA$aGFzaA", PepperKID: "3"},
		Roles:    []string{"member"}, GrantedBy: "system",
	}
	if phone != "" {
		a.Identifiers = append(a.Identifiers, account.NewIdentifier{ID: e.ids.New(), Type: "phone", Value: phone})
	}
	if email != "" {
		a.Identifiers = append(a.Identifiers, account.NewIdentifier{ID: e.ids.New(), Type: "email", Value: email})
	}
	return a
}

// create stores a in its own transaction.
func (e *accountsEnv) create(t *testing.T, a account.NewAccount) {
	t.Helper()
	e.do(t, func(ctx context.Context) error { return e.repo.Create(ctx, a) })
}

// exec runs a statement as superuser.
func (e *accountsEnv) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	exec(t, e.su, query, args...)
}

// checkCode fails the test unless err is a *domain.Error with code.
func checkCode(t *testing.T, err error, code domain.Code) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

// dbTimes ignores the times the database sets.
var dbTimes = cmpopts.IgnoreFields(account.Account{}, "StatusChangedAt", "CreatedAt", "UpdatedAt")

func TestCreateAndGet(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("+447700900123", "ada@example.org")
	e.create(t, na)

	got, err := e.repo.Get(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := account.Account{
		ID: na.ID, Status: account.StatusPending, DisplayName: "Ada Lovelace", Locale: "en-GB",
		RegisteredVia: "web", Version: 1,
	}
	if diff := cmp.Diff(want, got, dbTimes); diff != "" {
		t.Errorf("account (-want +got):\n%s", diff)
	}
	if got.CreatedAt.IsZero() || !got.CreatedAt.Equal(got.UpdatedAt) || !got.CreatedAt.Equal(got.StatusChangedAt) {
		t.Errorf("times = %v, %v, %v; want one database time", got.CreatedAt, got.UpdatedAt, got.StatusChangedAt)
	}
}

// TestCreateStoresNoPlaintext checks that the display name and the identifier values are stored
// encrypted, each bound to its own place (TDD-01 §3.1).
func TestCreateStoresNoPlaintext(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("+447700900123", "")
	e.create(t, na)

	var name, value, bidx []byte
	if err := e.su.QueryRowContext(t.Context(), "SELECT display_name FROM accounts WHERE id = ?", na.ID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	idID := na.Identifiers[0].ID
	if err := e.su.QueryRowContext(t.Context(), "SELECT value, value_bidx FROM identifiers WHERE id = ?", idID).
		Scan(&value, &bidx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		raw   []byte
		plain string
		place app.Place
	}{
		{name, "Ada Lovelace", app.NewPlace("accounts", "display_name", na.ID)},
		{value, "+447700900123", app.NewPlace("identifiers", "value", idID)},
	} {
		if bytes.Contains(c.raw, []byte(c.plain)) || bytes.Contains(c.raw, []byte("447700900123")) {
			t.Errorf("%s.%s holds its plaintext", c.place.Table, c.place.Column)
		}
		if got, err := e.fc.Open(c.place, c.raw); err != nil || string(got) != c.plain {
			t.Errorf("%s.%s opens to %q, %v; want %q", c.place.Table, c.place.Column, got, err, c.plain)
		}
		other := app.NewPlace(c.place.Table, c.place.Column, e.ids.New())
		if _, err := e.fc.Open(other, c.raw); !errors.Is(err, app.ErrCiphertextInvalid) {
			t.Errorf("%s.%s opens at another row: %v", c.place.Table, c.place.Column, err)
		}
	}
	want, err := e.bidx.Compute("phone", []byte("+447700900123"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bidx, want) {
		t.Errorf("value_bidx is not the blind index of the value")
	}
}

func TestGetNotFound(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	_, err := e.repo.Get(t.Context(), e.ids.New())
	checkCode(t, err, domain.CodeNotFound)
	err = e.uow.Do(t.Context(), func(ctx context.Context) error {
		_, err := e.repo.GetForUpdate(ctx, e.ids.New())
		return err
	})
	checkCode(t, err, domain.CodeNotFound)
}

// TestGetForUpdateOutsideTransaction checks that a lock outside UnitOfWork.Do, which would end
// with its statement, is refused.
func TestGetForUpdateOutsideTransaction(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	if _, err := e.repo.GetForUpdate(t.Context(), na.ID); !errors.Is(err, postgres.ErrNoTransaction) {
		t.Errorf("GetForUpdate outside Do: %v, want ErrNoTransaction", err)
	}
	// So is Create, whose rows must commit together.
	if err := e.repo.Create(t.Context(), e.newAccount("", "")); !errors.Is(err, postgres.ErrNoTransaction) {
		t.Errorf("Create outside Do: %v, want ErrNoTransaction", err)
	}
}

// TestCommitMovesVersion checks that a committed change moves the locked account's version by
// one and sets updated_at (TDD-01 §4.2).
func TestCommitMovesVersion(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	e.exec(t, "UPDATE accounts SET updated_at = now() - interval '1 hour' WHERE id = ?", na.ID)
	before, err := e.repo.Get(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}

	e.do(t, func(ctx context.Context) error {
		_, err := e.repo.GetForUpdate(ctx, na.ID)
		return err
	})
	after, err := e.repo.Get(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != 2 {
		t.Errorf("version = %d, want 2", after.Version)
	}
	if !after.UpdatedAt.After(before.UpdatedAt) {
		t.Errorf("updated_at = %v, want later than %v", after.UpdatedAt, before.UpdatedAt)
	}
}

// TestConcurrentUpdatesSerialise checks I-10: concurrent use cases that lock one account apply one
// after the other. Each reads the version under the lock and holds it a moment; without FOR UPDATE
// two would read the same version.
func TestConcurrentUpdatesSerialise(t *testing.T) {
	t.Parallel()
	const n = 8
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		read = map[int64]int{}
		errs = make(chan error, n)
	)
	for range n {
		wg.Go(func() {
			errs <- e.uow.Do(t.Context(), func(ctx context.Context) error {
				a, err := e.repo.GetForUpdate(ctx, na.ID)
				if err != nil {
					return err
				}
				time.Sleep(20 * time.Millisecond)
				mu.Lock()
				read[a.Version]++
				mu.Unlock()
				return nil
			})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	for v, k := range read {
		if k > 1 {
			t.Errorf("%d use cases read version %d under the lock", k, v)
		}
	}
	got, err := e.repo.Get(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1+n {
		t.Errorf("version = %d, want %d", got.Version, 1+n)
	}
}

// TestI17Check checks that the I-17 check finds an account that breaks it, so that it is not
// vacuous where accountsDB runs it.
func TestI17Check(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	if ids := accountsWithoutPassword(t, e.su); len(ids) != 0 {
		t.Fatalf("pending account with a password reported: %v", ids)
	}
	e.exec(t, "DELETE FROM password_credentials WHERE account_id = ?", na.ID)
	e.exec(t, "UPDATE accounts SET status = 'active' WHERE id = ?", na.ID)
	if diff := cmp.Diff([]uuid.UUID{na.ID}, accountsWithoutPassword(t, e.su)); diff != "" {
		t.Errorf("I-17 check (-want +got):\n%s", diff)
	}
	// Leave the database valid for the check at cleanup.
	e.exec(t, "UPDATE accounts SET status = 'pending' WHERE id = ?", na.ID)
}
