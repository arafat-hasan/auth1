package tokens

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// TypeAccess is the typ header of an access token (RFC 9068).
const TypeAccess = "at+jwt"

// Leeway is the clock skew allowed on exp, nbf and iat (TDD-04 §6 step 2 names exp and nbf; iat,
// which equals nbf in every token issued, gets the same; SDD A-4).
const Leeway = 30 * time.Second

// Config is what issuing and validation read from the configuration. NewIssuer and NewValidator
// refuse a Config they cannot work with; config.Validate already refuses every such deployment.
type Config struct {
	Issuer          string        // http.issuer; iss, compared exactly
	SelfAudience    string        // tokens.self_audience, the aud of restricted tokens; empty: Issuer
	AccessTTL       time.Duration // tokens.access_ttl
	ClientAudiences []string      // every client's audience, none the self audience; Validator only
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
	Roles  []string // all the account's roles, before the client's allowed_roles
}

// Client is the session's client, from the clients configuration (SDD D-6).
type Client struct {
	ID           string
	Audience     string
	AllowedRoles []string
}

// Access is an issued access token. It prints and logs without its token.
type Access struct {
	Token      string    // the compact JWS; a bearer credential, never logged
	ID         uuid.UUID // jti
	ExpiresAt  time.Time // exp
	Restricted bool      // true when issued to a restricted session, with the self audience
}

// String describes a without its token.
func (a Access) String() string {
	return fmt.Sprintf("tokens.Access{ID: %s, ExpiresAt: %s, Restricted: %t}",
		a.ID, a.ExpiresAt.Format(time.RFC3339), a.Restricted)
}

// GoString is String, for %#v.
func (a Access) GoString() string { return a.String() }

// Format writes String for every verb, so no verb prints the token.
func (a Access) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// LogValue logs a without its token.
func (a Access) LogValue() slog.Value {
	return slog.GroupValue(slog.String("jti", a.ID.String()), slog.Time("expires_at", a.ExpiresAt),
		slog.Bool("restricted", a.Restricted))
}

// Claims are the claims of a valid access token (TDD-04 §1).
type Claims struct {
	Issuer     string
	Subject    uuid.UUID // the account id
	Audience   string
	ExpiresAt  time.Time
	IssuedAt   time.Time
	NotBefore  time.Time
	ID         uuid.UUID // jti
	SessionID  uuid.UUID
	ClientID   string
	Roles      []string
	Status     account.Status // the account's status when the token was issued
	AMR        []string
	AuthTime   time.Time
	Restricted bool // a restricted session's token: suspended or banned, with the self audience
}

// ErrNotIssuable is the failure of IssueAccess for an account that may hold no token (pending,
// deleted, or a status it does not know), a session that is not the client's, or inputs missing
// an id, the client's audience or the sign-in time: a fault in the caller, never in a request.
var ErrNotIssuable = errors.New("tokens: no access token for this session")
