package contract

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/domain/message"
	"github.com/arafat-hasan/auth1/internal/testing/apitest"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
	"github.com/arafat-hasan/auth1/internal/testing/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// open returns a pool on dsn, closed when the test ends.
func open(t *testing.T, dsn string) *bun.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(path, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := postgres.Open(config.Database{
		DSNFile: config.NewSecretFile(path), MaxConns: 2, AcquireTimeout: 2 * time.Second,
	}, config.EnvDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestDeliveryRowsMatchContract builds a challenge code, a challenge link and a notice with the
// request builders, writes each through the outbox as a use case does, and checks the stored body
// against the contract's DeliveryRequest schema (WP-41 "Done when").
func TestDeliveryRowsMatchContract(t *testing.T) {
	t.Parallel()
	dsn := pgtest.DSN(t)
	appDB, su := open(t, pgtest.As(t, dsn, pgtest.App)), open(t, dsn)
	ids := fakes.NewIDs()
	outbox := postgres.NewOutbox(appDB, ids)
	uow := postgres.NewUnitOfWork(appDB, 5*time.Second, noop.NewTracerProvider())

	types, errs := message.NewTypes(nil)
	if errs != nil {
		t.Fatal(errs)
	}
	msgs := app.NewMessages(types)
	challenge := app.Challenge{ID: uuid.MustParse("0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8b"), Send: 2,
		ExpiresAt: time.Date(2026, 10, 26, 10, 5, 0, 0, time.UTC)}
	identifier := uuid.MustParse("0192f1c4-8d3a-7b2e-9f10-2c4d5e6f7a8c")

	code, err := msgs.ChallengeCode(message.PhoneVerificationCode, challenge, "en",
		app.ToIdentifier(identifier, message.SMS))
	if err != nil {
		t.Fatal(err)
	}
	link, err := msgs.ChallengeLink(message.EmailChangeConfirmNew, challenge, "en-GB",
		app.ToChallengeTarget(challenge.ID, message.Email))
	if err != nil {
		t.Fatal(err)
	}
	notice, err := msgs.Notice(message.NoticeRecoveryCodes, "en", app.ToIdentifier(identifier, message.Email),
		map[string]any{"change": "used", "remaining_codes": 3})
	if err != nil {
		t.Fatal(err)
	}
	shapes := []struct {
		name string
		req  app.DeliveryRequest
	}{{"code", code}, {"link", link}, {"notice", notice}}

	err = uow.Do(t.Context(), func(ctx context.Context) error {
		for _, s := range shapes {
			if err := outbox.Delivery(ctx, uuid.Nil, s.req); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("write the rows: %v", err)
	}

	rows, err := su.QueryContext(t.Context(), "SELECT id, type, body::text FROM outbox ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	v := apitest.New(t)
	i := 0
	for ; rows.Next(); i++ {
		var (
			id      uuid.UUID
			rowType string
			body    string
		)
		if err := rows.Scan(&id, &rowType, &body); err != nil {
			t.Fatal(err)
		}
		if i >= len(shapes) {
			t.Fatalf("more rows than shapes: %s", rowType)
		}
		s := shapes[i]
		t.Run(s.name, func(t *testing.T) {
			v.CheckSchema(t, "DeliveryRequest", []byte(body))
			var got struct {
				RequestID string  `json:"request_id"`
				Deadline  *string `json:"deadline"`
			}
			if err := json.Unmarshal([]byte(body), &got); err != nil {
				t.Fatal(err)
			}
			wantID, wantDeadline := s.req.RequestID, true
			if s.name == "notice" {
				wantID, wantDeadline = id.String(), false
			}
			if got.RequestID != wantID || (got.Deadline != nil) != wantDeadline {
				t.Errorf("request_id %q, deadline %v; want %q, deadline present %v",
					got.RequestID, got.Deadline, wantID, wantDeadline)
			}
		})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if i != len(shapes) {
		t.Errorf("%d rows, want %d", i, len(shapes))
	}
}
