package postgres

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// uniqueViolation is the SQLSTATE of a unique_violation.
const uniqueViolation = "23505"

// identifierTaken is the failure for a verified value that another account holds (I-1).
var identifierTaken = &domain.Error{Code: domain.CodeIdentifierTaken, Detail: "The identifier belongs to another account."}

// constraintError is the error of op failing with err. A unique violation of
// identifiers_verified_unique is IDENTIFIER_TAKEN, without err, whose detail names the indexed
// value; anything else, another constraint included, is a caller's bug or a database failure and
// is wrapped. It matches on the constraint name, never on the message.
func constraintError(op string, err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == uniqueViolation && pe.ConstraintName == "identifiers_verified_unique" {
		return identifierTaken
	}
	return fmt.Errorf("%s: %w", op, err)
}
