package tokens

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

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

// NewIssuer returns an issuer that signs with signer.
func NewIssuer(cfg Config, signer app.TokenSigner, clock app.Clock, ids app.IDGenerator) *Issuer {
	return &Issuer{cfg: cfg, signer: signer, clock: clock, ids: ids}
}

// IssueAccess returns an access token for session s of account a on client c, with the claims
// of TDD-04 §1. An active account gets a full token: the client's audience and the account's
// roles that the client allows. A suspended or banned account gets a restricted token: the self
// audience and no roles (SDD D-5). Any other status, or a session of another client, is
// ErrNotIssuable. While no key may sign it returns app.ErrNoSigningKey.
func (i *Issuer) IssueAccess(s Session, a Account, c Client) (Access, error) {
	if s.ClientID != c.ID {
		return Access{}, fmt.Errorf("%w: the session is not the client's", ErrNotIssuable)
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

// allowedRoles returns the roles in both have and allowed, sorted, each once; never nil.
func allowedRoles(have, allowed []string) []string {
	out := []string{}
	for _, r := range have {
		if slices.Contains(allowed, r) && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out
}
