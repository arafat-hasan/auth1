package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// uniqueViolation is the SQLSTATE of a unique_violation.
const uniqueViolation = "23505"

// identifierTaken is the failure for a verified value that another account holds (I-1), a new
// value each time, so a caller that changes one changes no other.
func identifierTaken() error {
	return &domain.Error{Code: domain.CodeIdentifierTaken, Detail: "The identifier belongs to another account."}
}

// constraintError is the error of op failing with err. A unique violation of
// identifiers_verified_unique is IDENTIFIER_TAKEN, without err, whose detail names the indexed
// value; anything else, another constraint included, is a caller's bug or a database failure and
// is wrapped. It matches on the constraint name, never on the message.
func constraintError(op string, err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == uniqueViolation && pe.ConstraintName == "identifiers_verified_unique" {
		return identifierTaken()
	}
	return fmt.Errorf("%s: %w", op, err)
}

// savepoint names the savepoint of withSavepoint.
const savepoint = "accounts_statement"

// withSavepoint runs exec, inside a transaction under a savepoint that a failure rolls back to.
// A failed statement otherwise aborts the whole transaction, and the use case could not go on
// after IDENTIFIER_TAKEN, as it must: it still consumes the challenge (TDD-02 §3). Outside a
// transaction the statement commits alone, and exec runs as it is.
func withSavepoint(ctx context.Context, db bun.IDB, exec func() (sql.Result, error)) (sql.Result, error) {
	if !inTx(ctx) {
		return exec()
	}
	if _, err := db.ExecContext(ctx, "SAVEPOINT "+savepoint); err != nil {
		return nil, fmt.Errorf("savepoint: %w", err)
	}
	res, err := exec()
	if err != nil {
		if _, rerr := db.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); rerr != nil {
			return nil, errors.Join(err, fmt.Errorf("roll back to savepoint: %w", rerr))
		}
		return nil, err
	}
	if _, err := db.ExecContext(ctx, "RELEASE SAVEPOINT "+savepoint); err != nil {
		return nil, fmt.Errorf("release savepoint: %w", err)
	}
	return res, nil
}
