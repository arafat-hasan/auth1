package tokens

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// payload is the claim set of an access token, in the order of the TDD-04 §1 table. Times are
// seconds since the epoch. Validate decodes the same struct.
type payload struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      string   `json:"aud"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	Nbf      int64    `json:"nbf"`
	Jti      string   `json:"jti"`
	Sid      string   `json:"sid"`
	ClientID string   `json:"client_id"`
	Roles    []string `json:"roles"`
	Status   string   `json:"status"`
	AMR      []string `json:"amr"`
	AuthTime int64    `json:"auth_time"`
}

// Issuer issues access tokens (TDD-04 §1).
type Issuer struct {
	cfg    Config
	signer app.TokenSigner
	clock  app.Clock
	ids    app.IDGenerator
}

// NewIssuer returns an issuer that signs with signer. It refuses a Config without an issuer or
// with an AccessTTL that is not positive.
func NewIssuer(cfg Config, signer app.TokenSigner, clock app.Clock, ids app.IDGenerator) (*Issuer, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("tokens: issuer: no issuer")
	}
	if cfg.AccessTTL <= 0 {
		return nil, fmt.Errorf("tokens: issuer: access TTL %s is not positive", cfg.AccessTTL)
	}
	return &Issuer{cfg: cfg, signer: signer, clock: clock, ids: ids}, nil
}

// IssueAccess returns an access token for session s of account a on client c, with the claims
// of TDD-04 §1. An active account gets a full token: the client's audience and the account's
// roles that the client allows. A suspended or banned account gets a restricted token: the self
// audience and no roles (SDD D-5). Any other status, a session of another client, a missing id,
// client audience or sign-in time, an empty amr value, or a client audience equal to the self
// audience is ErrNotIssuable. While no key may sign it returns an error matching
// app.ErrNoSigningKey; any other signer failure is returned wrapped.
func (i *Issuer) IssueAccess(s Session, a Account, c Client) (Access, error) {
	switch {
	case s.ClientID != c.ID:
		return Access{}, fmt.Errorf("%w: the session is not the client's", ErrNotIssuable)
	case s.ID == uuid.Nil || a.ID == uuid.Nil || c.ID == "" || c.Audience == "" || s.AuthTime.IsZero():
		return Access{}, fmt.Errorf("%w: a session, account or client without its id, audience or sign-in time", ErrNotIssuable)
	case c.Audience == i.cfg.selfAudience():
		return Access{}, fmt.Errorf("%w: the client's audience is the self audience", ErrNotIssuable)
	case slices.Contains(s.AMR, ""):
		return Access{}, fmt.Errorf("%w: an empty amr value", ErrNotIssuable)
	}
	restricted := account.Restricted(a.Status)
	if a.Status != account.StatusActive && !restricted {
		return Access{}, fmt.Errorf("%w: account status %s", ErrNotIssuable, a.Status)
	}

	now := i.clock.Now().Unix()
	exp := time.Unix(now, 0).Add(i.cfg.AccessTTL).Unix()
	jti := i.ids.New()
	p := payload{
		Iss:      i.cfg.Issuer,
		Sub:      a.ID.String(),
		Aud:      c.Audience,
		Exp:      exp,
		Iat:      now,
		Nbf:      now,
		Jti:      jti.String(),
		Sid:      s.ID.String(),
		ClientID: c.ID,
		Roles:    allowedRoles(a.Roles, c.AllowedRoles),
		Status:   string(a.Status),
		AMR:      append([]string{}, s.AMR...),
		AuthTime: s.AuthTime.Unix(),
	}
	if restricted {
		p.Aud = i.cfg.selfAudience()
		p.Roles = []string{}
	}
	body, err := json.Marshal(p)
	if err != nil {
		return Access{}, fmt.Errorf("access token claims: %w", err)
	}
	tok, err := i.signer.Sign(body, TypeAccess)
	if err != nil {
		return Access{}, fmt.Errorf("sign the access token: %w", err)
	}
	return Access{Token: tok, ID: jti, ExpiresAt: time.Unix(exp, 0).UTC(), Restricted: restricted}, nil
}

// allowedRoles returns the non-empty roles in both have and allowed, sorted, each once; never nil.
func allowedRoles(have, allowed []string) []string {
	out := []string{}
	for _, r := range have {
		if r != "" && slices.Contains(allowed, r) && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out
}

var _ app.AccessIssuer = (*Issuer)(nil)

// Issue implements app.AccessIssuer with IssueAccess.
func (i *Issuer) Issue(g app.AccessGrant) (app.AccessToken, error) {
	a, err := i.IssueAccess(
		Session{ID: g.SessionID, ClientID: g.ClientID, AMR: g.AMR, AuthTime: g.AuthTime},
		Account{ID: g.AccountID, Status: g.Status, Roles: g.Roles},
		Client{ID: g.ClientID, Audience: g.Audience, AllowedRoles: g.Allowed},
	)
	if err != nil {
		return app.AccessToken{}, err
	}
	return app.AccessToken{Token: a.Token, ExpiresAt: a.ExpiresAt, Restricted: a.Restricted}, nil
}
