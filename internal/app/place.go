package app

import (
	"encoding/hex"

	"github.com/google/uuid"
)

// Place is where an encrypted field is stored: its table, its column and its row (TDD-01 §3.1).
// Field ciphertext is bound to its place, so it does not open anywhere else (T-35). Build it with
// NewPlace or NewKeyPlace, so that Row is in the form the schema's key gives.
type Place struct {
	Table  string
	Column string
	Row    string
}

// NewPlace is the place of a column in a row whose primary key is a uuid: the row is the id in
// canonical lower-case hyphenated form.
func NewPlace(table, column string, id uuid.UUID) Place {
	return Place{Table: table, Column: column, Row: id.String()}
}

// NewKeyPlace is the place of a column in a row whose primary key is bytes (refresh_tokens'
// token_hash): the row is the key in lower-case hex.
func NewKeyPlace(table, column string, key []byte) Place {
	return Place{Table: table, Column: column, Row: hex.EncodeToString(key)}
}
