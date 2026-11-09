package app

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// AccessGrant is what an access token is issued from (TDD-04 §1): the session, the account at
// this moment and the client.
type AccessGrant struct {
	SessionID uuid.UUID
	ClientID  string
	AMR       []string
	AuthTime  time.Time
	AccountID uuid.UUID
	Status    account.Status
	Roles     []string // all the account's roles, before the client's allowed roles
	Audience  string   // the client's
	Allowed   []string // the client's allowed_roles
}

// AccessToken is an issued access token. It formats and logs without its token.
type AccessToken struct {
	Token      string // the compact JWS; a bearer credential, never logged
	ExpiresAt  time.Time
	Restricted bool // issued to a restricted session, with the self audience
}

// String describes t without its token.
func (t AccessToken) String() string {
	return fmt.Sprintf("app.AccessToken{ExpiresAt: %s, Restricted: %t}", t.ExpiresAt.Format(time.RFC3339), t.Restricted)
}

// GoString is String.
func (t AccessToken) GoString() string { return t.String() }

// Format writes String for every verb.
func (t AccessToken) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, t.String()) }

// LogValue implements slog.LogValuer with String.
func (t AccessToken) LogValue() slog.Value { return slog.StringValue(t.String()) }

// AccessIssuer issues access tokens (TDD-04 §1): tokens.Issuer. A full token for an active
// account, a restricted one for a suspended or banned account; any other status is an error.
type AccessIssuer interface {
	Issue(g AccessGrant) (AccessToken, error)
}
