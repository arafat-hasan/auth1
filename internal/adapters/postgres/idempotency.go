package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
)

// lockNotAvailable is the SQLSTATE of a lock wait past lock_timeout.
const lockNotAvailable = "55P03"

// claimLockTimeout bounds the wait for a transaction holding the same key (TDD-05 §4).
const claimLockTimeout = "5s"

// IdempotencyKeys implements app.IdempotencyKeys on idempotency_keys (TDD-05 §4, TDD-01 §4). The
// response is sealed at app.NewKeyPlace("idempotency_keys", "response", sha256(caller ‖ 0x00 ‖
// key)). Every time is the database's now().
type IdempotencyKeys struct {
	db *bun.DB
	fc app.FieldCrypto
}

// NewIdempotencyKeys returns the repository on db, sealing responses with fc.
func NewIdempotencyKeys(db *bun.DB, fc app.FieldCrypto) *IdempotencyKeys {
	return &IdempotencyKeys{db: db, fc: fc}
}

// sealedResponse is the plaintext of a sealed response.
type sealedResponse struct {
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

// place is where req's response is sealed.
func place(req app.IdempotencyRequest) app.Place {
	row := sha256.Sum256([]byte(req.Caller + "\x00" + req.Key))
	return app.NewKeyPlace("idempotency_keys", "response", row[:])
}

// Claim implements app.IdempotencyKeys. The key must be the transaction's first lock (TDD-01
// §4.2): after an account, flow, challenge or session lock it returns ErrLockOrder before
// querying, and outside a transaction ErrNoTransaction. One statement inserts the key, or takes
// over a row older than ttl. When another transaction holds the key uncommitted, that statement
// waits for it to end, at most 5 s (lock_timeout, then UNAVAILABLE). On a committed live row it
// leaves the row locked (ON CONFLICT DO UPDATE locks the row even when its WHERE refuses the
// update), and Claim reads it. lock_timeout is back to its default when Claim returns nil error;
// on an error the transaction is to be rolled back.
func (k *IdempotencyKeys) Claim(ctx context.Context, req app.IdempotencyRequest, ttl time.Duration) (*app.StoredIdempotency, error) {
	t := txFrom(ctx)
	if t == nil {
		return nil, fmt.Errorf("claim idempotency key: %w", ErrNoTransaction)
	}
	if len(t.locked) > 0 || len(t.flows) > 0 || len(t.challenges) > 0 || len(t.sessions) > 0 {
		return nil, fmt.Errorf("claim idempotency key after another lock: %w", ErrLockOrder)
	}
	if _, err := t.tx.ExecContext(ctx, "SET LOCAL lock_timeout = '"+claimLockTimeout+"'"); err != nil {
		return nil, fmt.Errorf("claim idempotency key: %w", err)
	}
	stored, err := k.claim(ctx, t.tx, req, ttl)
	if err != nil {
		return nil, err
	}
	if _, err := t.tx.ExecContext(ctx, "SET LOCAL lock_timeout TO DEFAULT"); err != nil {
		return nil, fmt.Errorf("claim idempotency key: %w", err)
	}
	return stored, nil
}

// claim runs Claim's statements: nil when it took the key, else the committed row.
func (k *IdempotencyKeys) claim(ctx context.Context, tx bun.Tx, req app.IdempotencyRequest, ttl time.Duration) (*app.StoredIdempotency, error) {
	var took bool
	err := tx.QueryRowContext(ctx, `
		INSERT INTO idempotency_keys AS k (caller, key, request_hash, created_at) VALUES (?, ?, ?, now())
		ON CONFLICT (caller, key) DO UPDATE
			SET request_hash = EXCLUDED.request_hash, status = NULL, response = NULL, created_at = now()
			WHERE k.created_at < now() - make_interval(secs => ?)
		RETURNING true`, req.Caller, req.Key, req.Hash, seconds(ttl)).Scan(&took)
	switch {
	case err == nil:
		return nil, nil
	case !errors.Is(err, sql.ErrNoRows):
		return nil, claimError(err)
	}

	var (
		stored app.StoredIdempotency
		status sql.NullInt64
		sealed []byte
	)
	err = tx.QueryRowContext(ctx, `
		SELECT request_hash, status, response FROM idempotency_keys WHERE caller = ? AND key = ? FOR UPDATE`,
		req.Caller, req.Key).Scan(&stored.Hash, &status, &sealed)
	if err != nil {
		return nil, claimError(err)
	}
	if !status.Valid || sealed == nil {
		return nil, errors.New("claim idempotency key: a committed row has no response")
	}
	plain, err := k.fc.Open(place(req), sealed)
	if err != nil {
		return nil, fmt.Errorf("open idempotency response: %w", err)
	}
	var r sealedResponse
	if err := json.Unmarshal(plain, &r); err != nil {
		return nil, fmt.Errorf("decode idempotency response: %w", err)
	}
	stored.Response = app.IdempotentResponse{Status: int(status.Int64), ContentType: r.ContentType, Body: r.Body}
	return &stored, nil
}

// claimError is UNAVAILABLE, retry in 1 s, for a wait past lock_timeout, else err wrapped.
func claimError(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == lockNotAvailable {
		return &domain.Error{Code: domain.CodeUnavailable, Detail: "The request is in progress; retry it with the same key.",
			RetryAfter: time.Second}
	}
	return fmt.Errorf("claim idempotency key: %w", err)
}

// Store implements app.IdempotencyKeys: it seals resp and records it on the key Claim took.
// Outside a transaction it returns ErrNoTransaction. A key this transaction did not claim, or has
// stored already, is a fault (a bug), never a domain refusal.
func (k *IdempotencyKeys) Store(ctx context.Context, req app.IdempotencyRequest, resp app.IdempotentResponse) error {
	t := txFrom(ctx)
	if t == nil {
		return fmt.Errorf("store idempotency response: %w", ErrNoTransaction)
	}
	plain, err := json.Marshal(sealedResponse{ContentType: resp.ContentType, Body: resp.Body})
	if err != nil {
		return fmt.Errorf("encode idempotency response: %w", err)
	}
	sealed, err := k.fc.Seal(place(req), plain)
	if err != nil {
		return fmt.Errorf("seal idempotency response: %w", err)
	}
	res, err := t.tx.ExecContext(ctx, `
		UPDATE idempotency_keys SET status = ?, response = ? WHERE caller = ? AND key = ? AND status IS NULL`,
		resp.Status, sealed, req.Caller, req.Key)
	if err != nil {
		return fmt.Errorf("store idempotency response: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store idempotency response: %w", err)
	}
	if n != 1 {
		return errors.New("store idempotency response: the key is not claimed, or already stored")
	}
	return nil
}
