package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
)

// errLimit is a lookup limit below 1: a caller's bug, refused rather than read as "none".
var errLimit = errors.New("postgres: limit must be at least 1")

// resumableKinds are the flow kinds resume serves (TDD-02 §4).
const resumableKinds = "f.kind IN ('registration', 'invitation')"

// Resumable implements app.Flows. It reads identifiers_lookup, then each account's flows through
// flows_account.
func (r *Flows) Resumable(ctx context.Context, idType, value string, limit int) ([]app.ResumeTarget, error) {
	const op = "find resumable flows"
	if limit < 1 {
		return nil, fmt.Errorf("%s: %w", op, errLimit)
	}
	bidx, err := r.bidx.Compute(idType, []byte(value))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	rows, err := Conn(ctx, r.db).QueryContext(ctx, "SELECT "+flowColumns+", i.id"+`
		FROM identifiers i JOIN flows f ON f.account_id = i.account_id
		WHERE i.type = ? AND i.value_bidx = ? AND i.retired_at IS NULL AND `+resumableKinds+` AND `+flowLive+`
		ORDER BY f.created_at DESC, f.id DESC
		LIMIT ?`, idType, bidx, limit)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()
	var out []app.ResumeTarget
	for rows.Next() {
		var idID uuid.UUID
		f, err := scanFlow(rows, &idID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		out = append(out, app.ResumeTarget{Flow: f, IdentifierID: idID})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return out, nil
}

// ResumeCandidates implements app.Flows. It reads challenges_target backwards, then each
// challenge's flow by its primary key.
func (r *Flows) ResumeCandidates(ctx context.Context, idType, value string, limit int) ([]app.ResumeCandidate, error) {
	const op = "find resume candidates"
	if limit < 1 {
		return nil, fmt.Errorf("%s: %w", op, errLimit)
	}
	bidx, err := r.bidx.Compute(idType, []byte(value))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	rows, err := Conn(ctx, r.db).QueryContext(ctx, "SELECT "+flowColumns+", "+challengeColumns+`
		FROM challenges c JOIN flows f ON f.id = c.flow_id
		WHERE c.target_bidx = ? AND c.purpose = 'resume' AND c.method <> 'email_link'
		  AND c.closed_at IS NULL AND c.expires_at > now() AND `+resumableKinds+` AND `+flowLive+`
		ORDER BY c.created_at DESC, c.id DESC
		LIMIT ?`, bidx, limit)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer func() { _ = rows.Close() }()
	var out []app.ResumeCandidate
	for rows.Next() {
		var c challengeRow
		f, err := scanFlow(rows, c.dest()...)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		rec, err := c.record()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		out = append(out, app.ResumeCandidate{Flow: f, Challenge: rec})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return out, nil
}
