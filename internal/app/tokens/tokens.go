package tokens

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// TypeAccess is the typ header of an access token (RFC 9068).
const TypeAccess = "at+jwt"

// Leeway is the clock skew allowed on exp, nbf and iat (TDD-04 §6 step 2; SDD A-4).
const Leeway = 30 * time.Second

// Config is what issuing and validation read from the configuration.
type Config struct {
	Issuer          string        // http.issuer; iss, compared exactly
	SelfAudience    string        // tokens.self_audience, the aud of restricted tokens; empty: Issuer
	AccessTTL       time.Duration // tokens.access_ttl
	ClientAudiences []string      // every client's audience; read by the Validator only
}

// selfAudience is the self audience: SelfAudience, or Issuer when it is empty.
func (c Config) selfAudience() string {
	if c.SelfAudience == "" {
		return c.Issuer
	}
	return c.SelfAudience
}

// Session is what a token says of its session (TDD-04 §2).
type Session struct {
	ID       uuid.UUID
	ClientID string
	AMR      []string  // the sign-in's amr (TDD-03 §7)
	AuthTime time.Time // the sign-in's time
}

// Account is what a token says of its account, read when the token is issued.
type Account struct {
	ID     uuid.UUID
	Status account.Status
	Roles  []string // the account's roles
}

// Client is the session's client, from the clients configuration (SDD D-6).
type Client struct {
	ID           string
	Audience     string
	AllowedRoles []string
}

// Access is an issued access token.
type Access struct {
	Token      string    // the compact JWS; a bearer credential, never logged
	ID         uuid.UUID // jti
	ExpiresAt  time.Time // exp
	Restricted bool      // true when issued to a restricted session, with the self audience
}

// Claims are the claims of a valid access token (TDD-04 §1).
type Claims struct {
	Issuer    string
	Subject   uuid.UUID // the account id
	Audience  string
	ExpiresAt time.Time
	IssuedAt  time.Time
	NotBefore time.Time
	ID        uuid.UUID // jti
	SessionID uuid.UUID
	ClientID  string
	Roles     []string
	Status    account.Status // the account's status when the token was issued
	AMR       []string
	AuthTime  time.Time
}

// ErrNotIssuable is the failure of IssueAccess for an account that may hold no token (pending,
// deleted, or a status it does not know) or a session that is not the client's: a fault in the
// caller, never in a request.
var ErrNotIssuable = errors.New("tokens: no access token for this session")
