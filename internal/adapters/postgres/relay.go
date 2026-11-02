package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"github.com/arafat-hasan/auth1/internal/app"
)

// noticeMaxAge is how long a notice may wait to be sent before it is dropped (TDD-06 §3.2).
const noticeMaxAge = 24 * time.Hour

// The last_error of rows the claim finishes without handing them to the relay (TDD-06 §3.2).
const (
	errChallengeClosed = "dropped: challenge closed"
	errNoticeExpired   = "dropped: notice expired"
	errBodyInvalid     = "parked: body invalid"
)

// errBody is a delivery body that is not a delivery request.
var errBody = errors.New("not a delivery request")

// DeliveryOutbox implements app.DeliveryOutbox on the outbox table (TDD-06 §3.2). The claim is a
// lease: one short transaction marks the claimed rows, so no transaction is open while the relay
// sends (G-4), and the outcome writes are fenced by the claimed attempts. Every time comparison is
// the database's now().
type DeliveryOutbox struct {
	db  *bun.DB
	uow *UnitOfWork
}

// NewDeliveryOutbox returns the relay's view of the outbox on db; the claim runs in uow.
func NewDeliveryOutbox(db *bun.DB, uow *UnitOfWork) *DeliveryOutbox {
	return &DeliveryOutbox{db: db, uow: uow}
}

// claimedRow is a due delivery row as the claim locks it.
type claimedRow struct {
	ID       uuid.UUID     `bun:"id"`
	Subject  uuid.NullUUID `bun:"subject"`
	Body     string        `bun:"body"`
	Attempts int           `bun:"attempts"`
	Expired  bool          `bun:"expired"` // created more than noticeMaxAge ago
}

// Claim implements app.DeliveryOutbox.
func (o *DeliveryOutbox) Claim(ctx context.Context, n int, lease time.Duration) ([]app.ClaimedDelivery, error) {
	var out []app.ClaimedDelivery
	err := o.uow.Do(ctx, func(ctx context.Context) error {
		out = nil
		db := Conn(ctx, o.db)
		var rows []claimedRow
		if err := db.NewRaw(`
			SELECT id, subject, body::text AS body, attempts, created_at < now() - ? * interval '1 microsecond' AS expired
			FROM outbox
			WHERE destination = 'delivery' AND published_at IS NULL AND parked_at IS NULL AND next_attempt_at <= now()
			ORDER BY next_attempt_at
			LIMIT ?
			FOR UPDATE SKIP LOCKED`, noticeMaxAge.Microseconds(), n).Scan(ctx, &rows); err != nil {
			return fmt.Errorf("claim deliveries: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}

		type decoded struct {
			row       claimedRow
			req       app.DeliveryRequest
			challenge uuid.UUID // zero for a notice
		}
		var ok []decoded
		var challenges []uuid.UUID
		finish := map[string][]uuid.UUID{} // last_error -> rows dropped or parked
		for _, r := range rows {
			req, challenge, err := decodeDelivery(r.Body)
			switch {
			case err != nil:
				finish[errBodyInvalid] = append(finish[errBodyInvalid], r.ID)
			case challenge == uuid.Nil && r.Expired:
				finish[errNoticeExpired] = append(finish[errNoticeExpired], r.ID)
			default:
				ok = append(ok, decoded{row: r, req: req, challenge: challenge})
				if challenge != uuid.Nil {
					challenges = append(challenges, challenge)
				}
			}
		}
		open, err := openChallenges(ctx, db, challenges)
		if err != nil {
			return err
		}
		var leased []uuid.UUID
		for _, d := range ok {
			if d.challenge != uuid.Nil && !open[d.challenge] {
				finish[errChallengeClosed] = append(finish[errChallengeClosed], d.row.ID)
				continue
			}
			leased = append(leased, d.row.ID)
			out = append(out, app.ClaimedDelivery{
				Attempt: d.row.Attempts + 1,
				Row:     app.DeliveryRow{ID: d.row.ID, AccountID: d.row.Subject.UUID, Request: d.req},
			})
		}
		for lastError, ids := range finish {
			col := "published_at"
			if lastError == errBodyInvalid {
				col = "parked_at"
			}
			if _, err := db.NewRaw(`UPDATE outbox SET ? = now(), last_error = ? WHERE id = ANY(?)`,
				bun.Ident(col), lastError, pgdialect.Array(ids)).Exec(ctx); err != nil {
				return fmt.Errorf("finish deliveries: %w", err)
			}
		}
		if len(leased) > 0 {
			if _, err := db.NewRaw(`
				UPDATE outbox SET attempts = attempts + 1, next_attempt_at = now() + ? * interval '1 microsecond'
				WHERE id = ANY(?)`, lease.Microseconds(), pgdialect.Array(leased)).Exec(ctx); err != nil {
				return fmt.Errorf("lease deliveries: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// openChallenges returns which of ids name a challenge that is open under TDD-06 §6 rule 2: not
// closed, not expired and not out of attempts. A purged challenge is not open.
func openChallenges(ctx context.Context, db bun.IDB, ids []uuid.UUID) (map[uuid.UUID]bool, error) {
	open := map[uuid.UUID]bool{}
	if len(ids) == 0 {
		return open, nil
	}
	var found []uuid.UUID
	if err := db.NewRaw(`
		SELECT id FROM challenges
		WHERE id = ANY(?) AND closed_at IS NULL AND expires_at > now() AND attempts < max_attempts`,
		pgdialect.Array(ids)).Scan(ctx, &found); err != nil {
		return nil, fmt.Errorf("read challenges: %w", err)
	}
	for _, id := range found {
		open[id] = true
	}
	return open, nil
}

// decodeDelivery decodes a delivery row's body (deliveryBody) and returns the challenge its
// request_id names, "<challenge id>:<send number>"; zero for a notice, whose request_id has no
// colon. Integer variables come back as int64; a variable that is neither a string nor an
// integer is refused, as Messages refuses it when building (TDD-06 §5).
func decodeDelivery(body string) (app.DeliveryRequest, uuid.UUID, error) {
	var b struct {
		RequestID string                     `json:"request_id"`
		Type      string                     `json:"type"`
		Channel   string                     `json:"channel"`
		Locale    string                     `json:"locale"`
		Recipient string                     `json:"recipient"`
		Variables map[string]json.RawMessage `json:"variables"`
		Deadline  *time.Time                 `json:"deadline"`
	}
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		return app.DeliveryRequest{}, uuid.Nil, errBody
	}
	if b.RequestID == "" || b.Type == "" || b.Channel == "" || b.Recipient == "" {
		return app.DeliveryRequest{}, uuid.Nil, errBody
	}
	vars := make(map[string]any, len(b.Variables))
	for k, v := range b.Variables {
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			vars[k] = s
			continue
		}
		d := json.NewDecoder(bytes.NewReader(v))
		d.UseNumber()
		var num json.Number
		if err := d.Decode(&num); err != nil {
			return app.DeliveryRequest{}, uuid.Nil, errBody
		}
		i, err := num.Int64()
		if err != nil {
			return app.DeliveryRequest{}, uuid.Nil, errBody
		}
		vars[k] = i
	}
	var challenge uuid.UUID
	if head, _, found := strings.Cut(b.RequestID, ":"); found {
		id, err := uuid.Parse(head)
		if err != nil {
			return app.DeliveryRequest{}, uuid.Nil, errBody
		}
		challenge = id
	}
	return app.DeliveryRequest{
		RequestID: b.RequestID, Type: b.Type, Channel: b.Channel, Locale: b.Locale,
		Recipient: b.Recipient, Variables: vars, Deadline: b.Deadline,
	}, challenge, nil
}

// Publish implements app.DeliveryOutbox.
func (o *DeliveryOutbox) Publish(ctx context.Context, c app.ClaimedDelivery, lastError string) error {
	return o.finish(ctx, c, "published_at = now(), last_error = nullif(?, '')", lastError)
}

// Retry implements app.DeliveryOutbox. LEAST ignores the null deadline of a notice.
func (o *DeliveryOutbox) Retry(ctx context.Context, c app.ClaimedDelivery, delay time.Duration, reason string) error {
	return o.finish(ctx, c, `
		next_attempt_at = LEAST(now() + ? * interval '1 microsecond', (body->>'deadline')::timestamptz),
		last_error = ?`, delay.Microseconds(), reason)
}

// Park implements app.DeliveryOutbox.
func (o *DeliveryOutbox) Park(ctx context.Context, c app.ClaimedDelivery, reason string) error {
	return o.finish(ctx, c, "parked_at = now(), last_error = ?", reason)
}

// finish applies set to the claimed row while it is still leased to c, or returns ErrClaimLost.
func (o *DeliveryOutbox) finish(ctx context.Context, c app.ClaimedDelivery, set string, args ...any) error {
	args = append(args, c.Row.ID, c.Attempt)
	res, err := Conn(ctx, o.db).NewRaw(`UPDATE outbox SET `+set+`
		WHERE id = ? AND attempts = ? AND published_at IS NULL AND parked_at IS NULL`, args...).Exec(ctx)
	if err != nil {
		return fmt.Errorf("record delivery outcome: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("record delivery outcome: %w", err)
	}
	if n == 0 {
		return app.ErrClaimLost
	}
	return nil
}

// Stats implements app.DeliveryOutbox.
func (o *DeliveryOutbox) Stats(ctx context.Context) (app.OutboxStats, error) {
	var age sql.NullFloat64
	var parked int
	err := Conn(ctx, o.db).NewRaw(`
		SELECT extract(epoch FROM now() - min(created_at) FILTER (WHERE parked_at IS NULL)),
		       count(*) FILTER (WHERE parked_at IS NOT NULL)
		FROM outbox WHERE destination = 'delivery' AND published_at IS NULL`).Scan(ctx, &age, &parked)
	if err != nil {
		return app.OutboxStats{}, fmt.Errorf("read delivery backlog: %w", err)
	}
	return app.OutboxStats{OldestAge: time.Duration(age.Float64 * float64(time.Second)), Parked: parked}, nil
}
