package tokens

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// ErrInvalid matches every refusal of Validate: errors.Is(err, ErrInvalid) tells a refused token
// from any other failure. The refusals below say which check failed, for tests and metrics; a
// caller answers them all alike (TOKEN_INVALID, or an inactive introspection).
var ErrInvalid = errors.New("tokens: invalid access token")

// The refusals of Validate, in the order it checks. Their text is fixed: none holds any part of
// the token.
var (
	ErrMalformed   error = refusal("not a compact JWS with the header of an access token")
	ErrType        error = refusal("typ is not " + TypeAccess)
	ErrUnknownKey  error = refusal("kid is not a published key")
	ErrAlgorithm   error = refusal("alg is not the key's")
	ErrSignature   error = refusal("bad signature")
	ErrClaims      error = refusal("claims missing or malformed")
	ErrIssuer      error = refusal("wrong issuer")
	ErrAudience    error = refusal("audience not accepted")
	ErrExpired     error = refusal("expired")
	ErrNotYetValid error = refusal("not yet valid")
)

// refusal is a reason Validate refuses a token. It matches ErrInvalid.
type refusal string

func (r refusal) Error() string { return "tokens: access token refused: " + string(r) }

// Is reports whether target is ErrInvalid.
func (refusal) Is(target error) bool { return target == ErrInvalid }

// maxTokenSize bounds the token Validate parses. An issued token is well under 2 KiB.
const maxTokenSize = 8 << 10

// headerKeys are the only protected header parameters an access token has. Any other (jku, jwk,
// x5u, crit, b64, …) is refused rather than ignored.
var headerKeys = []string{jws.AlgorithmKey, jws.KeyIDKey, jws.TypeKey}

// Validator validates access tokens (TDD-04 §6 steps 1–2).
type Validator struct {
	issuer    string
	audiences []string // the clients' audiences and the self audience
	keys      app.PublicKeys
	clock     app.Clock
}

// NewValidator returns a validator over the published keys. It accepts tokens of cfg.Issuer
// whose audience is one of cfg.ClientAudiences or the self audience (TDD-04 §1, §6 step 2).
func NewValidator(cfg Config, keys app.PublicKeys, clock app.Clock) *Validator {
	auds := append(slices.Clone(cfg.ClientAudiences), cfg.selfAudience())
	return &Validator{issuer: cfg.Issuer, audiences: auds, keys: keys, clock: clock}
}

// Validate returns the claims of token, or one of the refusals above. It checks, in order: a
// compact JWS (so one signature) of at most 8 KiB with only alg, kid and typ in its protected
// header; typ at+jwt; a published kid; the header's alg equal to that key's own (never
// none), so the token never chooses the algorithm; the signature, verified with the key's
// alg; every claim of TDD-04 §1, with its type; iss exactly; aud accepted; exp, nbf and iat with
// Leeway against the clock.
func (v *Validator) Validate(token string) (Claims, error) {
	pk, err := v.key(token)
	if err != nil {
		return Claims{}, err
	}
	alg, ok := jwa.LookupSignatureAlgorithm(pk.Alg)
	if !ok {
		return Claims{}, ErrAlgorithm
	}
	body, err := jws.Verify([]byte(token), jws.WithCompact(), jws.WithKey(alg, pk.Key))
	if err != nil {
		return Claims{}, ErrSignature
	}
	c, err := parseClaims(body)
	if err != nil {
		return Claims{}, err
	}
	if c.Issuer != v.issuer {
		return Claims{}, ErrIssuer
	}
	if !slices.Contains(v.audiences, c.Audience) {
		return Claims{}, ErrAudience
	}
	now := v.clock.Now()
	if now.After(c.ExpiresAt.Add(Leeway)) {
		return Claims{}, ErrExpired
	}
	if now.Before(c.NotBefore.Add(-Leeway)) || now.Before(c.IssuedAt.Add(-Leeway)) {
		return Claims{}, ErrNotYetValid
	}
	return c, nil
}

// key checks the token's form and protected header and returns the published key it names,
// whose alg the header's must equal.
func (v *Validator) key(token string) (app.PublicKey, error) {
	if len(token) > maxTokenSize {
		return app.PublicKey{}, ErrMalformed
	}
	msg, err := jws.Parse([]byte(token), jws.WithCompact())
	if err != nil {
		return app.PublicKey{}, ErrMalformed
	}
	h := msg.Signatures()[0].ProtectedHeaders()
	for _, k := range h.Keys() {
		if !slices.Contains(headerKeys, k) {
			return app.PublicKey{}, ErrMalformed
		}
	}
	if typ, ok := h.Type(); !ok || typ != TypeAccess {
		return app.PublicKey{}, ErrType
	}
	kid, ok := h.KeyID()
	if !ok {
		return app.PublicKey{}, ErrUnknownKey
	}
	pk, ok := v.keys.Key(kid)
	if !ok {
		return app.PublicKey{}, ErrUnknownKey
	}
	// The key fixes the alg: none, or any alg other than the key's, is refused here.
	if alg, _ := h.Algorithm(); alg.String() != pk.Alg {
		return app.PublicKey{}, ErrAlgorithm
	}
	return pk, nil
}

// claimNames are the claims of TDD-04 §1; a token without any of them is refused.
var claimNames = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "sid", "client_id", "roles", "status", "amr", "auth_time"}

// parseClaims decodes the verified payload. Every claim of TDD-04 §1 must be present, non-null
// and of its type; other claims are ignored.
func parseClaims(body []byte) (Claims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return Claims{}, ErrClaims
	}
	for _, name := range claimNames {
		if v, ok := raw[name]; !ok || bytes.Equal(v, []byte("null")) {
			return Claims{}, ErrClaims
		}
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return Claims{}, ErrClaims
	}
	sub, err1 := uuid.Parse(p.Sub)
	jti, err2 := uuid.Parse(p.Jti)
	sid, err3 := uuid.Parse(p.Sid)
	status, err4 := account.ParseStatus(p.Status)
	if errors.Join(err1, err2, err3, err4) != nil ||
		(status != account.StatusActive && !account.Restricted(status)) {
		return Claims{}, ErrClaims
	}
	return Claims{
		Issuer:    p.Iss,
		Subject:   sub,
		Audience:  p.Aud,
		ExpiresAt: unix(p.Exp),
		IssuedAt:  unix(p.Iat),
		NotBefore: unix(p.Nbf),
		ID:        jti,
		SessionID: sid,
		ClientID:  p.ClientID,
		Roles:     p.Roles,
		Status:    status,
		AMR:       p.AMR,
		AuthTime:  unix(p.AuthTime),
	}, nil
}

func unix(s int64) time.Time { return time.Unix(s, 0).UTC() }
