package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/flow"
)

// challengeColumns are the columns challengeRow reads, in its order.
const challengeColumns = `c.id, c.flow_id, c.purpose, c.method, c.identifier_id, c.secret_mac, c.sends, c.created_at,
	c.attempts, c.max_attempts, c.last_sent_at, c.expires_at, c.consumed_at, c.closed_at`

// challengeRow is the scan target of challengeColumns.
type challengeRow struct {
	rec                    flow.ChallengeRecord
	purpose, method        string
	identifier             uuid.NullUUID
	sent, consumed, closed sql.NullTime
}

// dest returns the scan destinations, in challengeColumns' order.
func (c *challengeRow) dest() []any {
	r := &c.rec
	return []any{&r.ID, &r.FlowID, &c.purpose, &c.method, &c.identifier, &r.SecretMAC, &r.Sends, &r.CreatedAt,
		&r.Attempts, &r.MaxAttempts, &c.sent, &r.ExpiresAt, &c.consumed, &c.closed}
}

// record returns the scanned record.
func (c *challengeRow) record() (flow.ChallengeRecord, error) {
	r := c.rec
	var err error
	if r.Purpose, err = flow.ParsePurpose(c.purpose); err != nil {
		return flow.ChallengeRecord{}, err
	}
	if r.Method, err = flow.ParseMethod(c.method); err != nil {
		return flow.ChallengeRecord{}, err
	}
	if c.identifier.Valid {
		id := c.identifier.UUID
		r.IdentifierID = &id
	}
	r.LastSentAt, r.ConsumedAt, r.ClosedAt = timePtr(c.sent), timePtr(c.consumed), timePtr(c.closed)
	r.ExpiresAt, r.CreatedAt = r.ExpiresAt.UTC(), r.CreatedAt.UTC()
	return r, nil
}

// FindLink implements app.Flows. It reads challenges_link, the unique index of link hashes.
func (r *Flows) FindLink(ctx context.Context, linkHash []byte) (flow.Flow, flow.ChallengeRecord, error) {
	var c challengeRow
	f, err := scanFlow(Conn(ctx, r.db).QueryRowContext(ctx, "SELECT "+flowColumns+", "+challengeColumns+`
		FROM challenges c JOIN flows f ON f.id = c.flow_id
		WHERE c.method = 'email_link' AND c.secret_mac = ? AND c.closed_at IS NULL AND c.expires_at > now()
		  AND `+flowLive, linkHash), c.dest()...)
	if errors.Is(err, sql.ErrNoRows) {
		return flow.Flow{}, flow.ChallengeRecord{}, flowClosed()
	}
	if err != nil {
		return flow.Flow{}, flow.ChallengeRecord{}, fmt.Errorf("find link: %w", err)
	}
	rec, err := c.record()
	if err != nil {
		return flow.Flow{}, flow.ChallengeRecord{}, fmt.Errorf("find link: %w", err)
	}
	return f, rec, nil
}

// LockChallenges implements app.Flows.
func (r *Flows) LockChallenges(ctx context.Context, flowID uuid.UUID) ([]flow.ChallengeRecord, error) {
	t, err := lockedFlow(ctx, "lock challenges", flowID)
	if err != nil {
		return nil, err
	}
	rows, err := t.tx.QueryContext(ctx, "SELECT "+challengeColumns+
		" FROM challenges c WHERE c.flow_id = ? ORDER BY c.created_at, c.id FOR UPDATE", flowID)
	if err != nil {
		return nil, fmt.Errorf("lock challenges: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var cs []flow.ChallengeRecord
	for rows.Next() {
		var c challengeRow
		if err := rows.Scan(c.dest()...); err != nil {
			return nil, fmt.Errorf("lock challenges: %w", err)
		}
		rec, err := c.record()
		if err != nil {
			return nil, fmt.Errorf("lock challenges: %w", err)
		}
		cs = append(cs, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("lock challenges: %w", err)
	}
	for _, c := range cs {
		t.lockChallenge(c.ID)
	}
	return cs, nil
}

// OpenChallenge implements app.Flows.
func (r *Flows) OpenChallenge(ctx context.Context, c flow.NewChallengeRecord) error {
	t, err := lockedFlow(ctx, "open challenge", c.FlowID)
	if err != nil {
		return err
	}
	if _, err := flow.ParsePurpose(string(c.Purpose)); err != nil {
		return fmt.Errorf("open challenge: %w", err)
	}
	if _, err := flow.ParseMethod(string(c.Method)); err != nil {
		return fmt.Errorf("open challenge: %w", err)
	}
	bidx, err := r.bidx.Compute(c.TargetType, []byte(c.TargetValue))
	if err != nil {
		return fmt.Errorf("open challenge: %w", err)
	}
	secret, err := r.fc.Seal(app.NewPlace(tableChallenges, "secret", c.ID), c.Secret)
	if err != nil {
		return fmt.Errorf("open challenge: %w", err)
	}
	var target []byte
	if c.IdentifierID == nil {
		if target, err = r.fc.Seal(app.NewPlace(tableChallenges, "target_value", c.ID), []byte(c.TargetValue)); err != nil {
			return fmt.Errorf("open challenge: %w", err)
		}
	}
	if _, err := t.tx.ExecContext(ctx, `
		INSERT INTO challenges (id, flow_id, purpose, method, identifier_id, target_value, target_bidx, secret_mac,
			secret, max_attempts, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now())`,
		c.ID, c.FlowID, string(c.Purpose), string(c.Method), c.IdentifierID, target, bidx, c.SecretMAC,
		secret, c.MaxAttempts, c.ExpiresAt); err != nil {
		return fmt.Errorf("open challenge: %w", err)
	}
	t.lockChallenge(c.ID)
	return nil
}

// lockedChallenge returns the transaction, or the error of op when ctx carries none or the
// challenge id is not locked in it.
func lockedChallenge(ctx context.Context, op string, id uuid.UUID) (*txn, error) {
	t := txFrom(ctx)
	if t == nil {
		return nil, fmt.Errorf("%s: %w", op, ErrNoTransaction)
	}
	if !slices.Contains(t.challenges, id) {
		return nil, fmt.Errorf("%s: %w", op, ErrLockOrder)
	}
	return t, nil
}

// ChallengeSecret implements app.Flows.
func (r *Flows) ChallengeSecret(ctx context.Context, id uuid.UUID) (flow.Secret, error) {
	plain, err := r.openColumn(ctx, "read challenge secret", id, "secret", "closed_at IS NULL")
	return flow.Secret(plain), err
}

// ChallengeTarget implements app.Flows.
func (r *Flows) ChallengeTarget(ctx context.Context, id uuid.UUID) (string, error) {
	plain, err := r.openColumn(ctx, "read challenge target", id, "target_value", "true")
	return string(plain), err
}

// openColumn decrypts column of the locked challenge id where cond holds; NOT_FOUND when it does
// not, or the column is null.
func (r *Flows) openColumn(ctx context.Context, op string, id uuid.UUID, column, cond string) ([]byte, error) {
	t, err := lockedChallenge(ctx, op, id)
	if err != nil {
		return nil, err
	}
	var sealed []byte
	err = t.tx.QueryRowContext(ctx, "SELECT "+column+" FROM challenges WHERE id = ? AND "+cond, id).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) || err == nil && sealed == nil {
		return nil, notFound("challenge " + column)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	plain, err := r.fc.Open(app.NewPlace(tableChallenges, column, id), sealed)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return plain, nil
}

// Attempt implements app.Flows. The condition is I-4's: no try counts on a closed challenge or
// past max_attempts, whatever the caller decided.
func (r *Flows) Attempt(ctx context.Context, id uuid.UUID) (int, bool, error) {
	t, err := lockedChallenge(ctx, "count attempt", id)
	if err != nil {
		return 0, false, err
	}
	var attempts int
	err = t.tx.QueryRowContext(ctx, `
		UPDATE challenges SET attempts = attempts + 1
		WHERE id = ? AND closed_at IS NULL AND attempts < max_attempts
		RETURNING attempts`, id).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("count attempt: %w", err)
	}
	return attempts, true, nil
}

// RecordSend implements app.Flows. The send's row in challenge_sends, which the send limits
// count, is written in the same statement.
func (r *Flows) RecordSend(ctx context.Context, id uuid.UUID) (int, error) {
	t, err := lockedChallenge(ctx, "record send", id)
	if err != nil {
		return 0, err
	}
	var sends int
	err = t.tx.QueryRowContext(ctx, `
		WITH c AS (
			UPDATE challenges SET sends = sends + 1, last_sent_at = now()
			WHERE id = ? AND closed_at IS NULL
			RETURNING id, sends, target_bidx, last_sent_at)
		INSERT INTO challenge_sends (challenge_id, send, target_bidx, sent_at)
		SELECT id, sends, target_bidx, last_sent_at FROM c
		RETURNING send`, id).Scan(&sends)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, notFound("challenge")
	}
	if err != nil {
		return 0, fmt.Errorf("record send: %w", err)
	}
	return sends, nil
}

// CloseChallenge implements app.Flows. Closing and erasing are one statement (I-5); the
// closed_at condition makes a second consumption change nothing (I-4).
func (r *Flows) CloseChallenge(ctx context.Context, id uuid.UUID, consumed bool) (bool, error) {
	t, err := lockedChallenge(ctx, "close challenge", id)
	if err != nil {
		return false, err
	}
	res, err := t.tx.ExecContext(ctx, `
		UPDATE challenges SET closed_at = now(), consumed_at = CASE WHEN ? THEN now() END, secret = NULL
		WHERE id = ? AND closed_at IS NULL`, consumed, id)
	if err != nil {
		return false, fmt.Errorf("close challenge: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("close challenge: %w", err)
	}
	return n == 1, nil
}
