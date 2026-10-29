package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/app"
)

// SigningKeys implements app.SigningKeyStore on signing_keys (TDD-04 §5.2). Every time is the
// database's now().
type SigningKeys struct {
	db *bun.DB
}

// NewSigningKeys returns the store on db.
func NewSigningKeys(db *bun.DB) *SigningKeys {
	return &SigningKeys{db: db}
}

// seconds is d as fractional seconds, for make_interval(secs => ?), to the microsecond.
func seconds(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1e6
}

// Publish implements app.SigningKeyStore.
func (s *SigningKeys) Publish(ctx context.Context, keys []app.SigningKeyRecord) error {
	if len(keys) == 0 {
		return nil
	}
	q := "INSERT INTO signing_keys (kid, alg, first_published_at) VALUES "
	args := make([]any, 0, 2*len(keys))
	for i, k := range keys {
		if i > 0 {
			q += ", "
		}
		q += "(?, ?, now())"
		args = append(args, k.Kid, k.Alg)
	}
	if _, err := Conn(ctx, s.db).ExecContext(ctx, q+" ON CONFLICT (kid) DO NOTHING", args...); err != nil {
		return fmt.Errorf("publish signing keys: %w", err)
	}
	return nil
}

// Activate implements app.SigningKeyStore.
func (s *SigningKeys) Activate(ctx context.Context, kid string, minPublish time.Duration) (bool, error) {
	var got string
	err := Conn(ctx, s.db).QueryRowContext(ctx, `
		UPDATE signing_keys SET activated_at = now(), retired_at = NULL
		WHERE kid = ? AND first_published_at <= now() - make_interval(secs => ?)
		RETURNING kid`, kid, seconds(minPublish)).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("activate signing key: %w", err)
	}
	return true, nil
}

// KeepSigning implements app.SigningKeyStore.
func (s *SigningKeys) KeepSigning(ctx context.Context, kid string) error {
	_, err := Conn(ctx, s.db).ExecContext(ctx,
		"UPDATE signing_keys SET activated_at = now(), retired_at = NULL WHERE kid = ?", kid)
	if err != nil {
		return fmt.Errorf("keep the previous signing key: %w", err)
	}
	return nil
}

// LatestActivated implements app.SigningKeyStore.
func (s *SigningKeys) LatestActivated(ctx context.Context, kids []string) (string, error) {
	if len(kids) == 0 {
		return "", nil
	}
	var kid string
	err := Conn(ctx, s.db).QueryRowContext(ctx, `
		SELECT kid FROM signing_keys WHERE kid IN (?) AND activated_at IS NOT NULL
		ORDER BY activated_at DESC, kid LIMIT 1`, bun.List(kids)).Scan(&kid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("find the previous signing key: %w", err)
	}
	return kid, nil
}

// Retire implements app.SigningKeyStore.
func (s *SigningKeys) Retire(ctx context.Context, kids []string) error {
	if len(kids) == 0 {
		return nil
	}
	_, err := Conn(ctx, s.db).ExecContext(ctx,
		"UPDATE signing_keys SET retired_at = now() WHERE kid IN (?) AND retired_at IS NULL", bun.List(kids))
	if err != nil {
		return fmt.Errorf("retire signing keys: %w", err)
	}
	return nil
}

// Retiring implements app.SigningKeyStore. The kids come back sorted.
func (s *SigningKeys) Retiring(ctx context.Context, kids []string, window time.Duration) ([]string, error) {
	if len(kids) == 0 {
		return nil, nil
	}
	rows, err := Conn(ctx, s.db).QueryContext(ctx, `
		SELECT kid FROM signing_keys
		WHERE kid IN (?) AND (retired_at IS NULL OR retired_at > now() - make_interval(secs => ?))
		ORDER BY kid`, bun.List(kids), seconds(window))
	if err != nil {
		return nil, fmt.Errorf("read retiring signing keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var kid string
		if err := rows.Scan(&kid); err != nil {
			return nil, fmt.Errorf("read retiring signing keys: %w", err)
		}
		out = append(out, kid)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read retiring signing keys: %w", err)
	}
	return out, nil
}
