package tokens

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// ErrInvalid matches every refusal of Validate. The refusals below say which check failed, for
// tests; a caller answers them all alike (TOKEN_INVALID, or an inactive introspection). The one
// error of Validate that does not match it is ErrKeyUnusable.
var ErrInvalid = errors.New("tokens: invalid access token")

// The refusals of Validate, in the order it checks. Their text is fixed: none holds any part of
// the token.
var (
	ErrMalformed   error = refusal("not a compact JWS with the header of an access token")
	ErrType        error = refusal("typ is not " + TypeAccess)
	ErrUnknownKey  error = refusal("kid is not a published key")
	ErrAlgorithm   error = refusal("alg is not the key's")
	ErrSignature   error = refusal("bad signature")
	ErrClaims      error = refusal("claims missing, malformed or inconsistent")
	ErrIssuer      error = refusal("wrong issuer")
	ErrAudience    error = refusal("audience not accepted for this status")
	ErrExpired     error = refusal("expired")
	ErrNotYetValid error = refusal("not yet valid")
)

// ErrKeyUnusable is Validate's failure when the published key a token names cannot verify: an alg
// other than RS256 or ES256, or a public key of another type or curve. It is a keyring fault, not
// a bad token, so it does not match ErrInvalid; a caller answers it as a server error and logs it.
var ErrKeyUnusable = errors.New("tokens: the published key cannot verify")

// refusal is a reason Validate refuses a token. It matches ErrInvalid.
type refusal string

func (r refusal) Error() string { return "tokens: access token refused: " + string(r) }

// Is reports whether target is ErrInvalid.
func (refusal) Is(target error) bool { return target == ErrInvalid }

// maxTokenSize bounds the token Validate parses. A token issued with a few roles is under 1 KiB;
// the bound leaves room for many.
const maxTokenSize = 8 << 10

// headerKeys are the only protected header parameters an access token has. Any other (jku, jwk,
// x5u, crit, b64, …) is refused rather than ignored.
var headerKeys = []string{jws.AlgorithmKey, jws.KeyIDKey, jws.TypeKey}

// keyTypes are the algorithms a published key may have, each with the public key type it needs.
var keyTypes = map[string]func(any) bool{
	"RS256": func(k any) bool { _, ok := k.(*rsa.PublicKey); return ok },
	"ES256": func(k any) bool { e, ok := k.(*ecdsa.PublicKey); return ok && e.Curve == elliptic.P256() },
}

// Validator validates access tokens (TDD-04 §6 steps 1–2).
type Validator struct {
	issuer    string
	self      string   // the self audience
	audiences []string // the clients' audiences and the self audience
	keys      app.PublicKeys
	clock     app.Clock
}

// NewValidator returns a validator over the published keys. It accepts tokens of cfg.Issuer
// whose audience is one of cfg.ClientAudiences or the self audience (TDD-04 §1, §6 step 2). It
// refuses a Config without an issuer, or with a client audience that is empty, repeated or the
// self audience: full and restricted tokens must be told apart by audience alone (SDD D-5).
func NewValidator(cfg Config, keys app.PublicKeys, clock app.Clock) (*Validator, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("tokens: validator: no issuer")
	}
	self := cfg.selfAudience()
	for i, aud := range cfg.ClientAudiences {
		switch {
		case aud == "":
			return nil, fmt.Errorf("tokens: validator: client audience %d is empty", i)
		case aud == self:
			return nil, fmt.Errorf("tokens: validator: client audience %q is the self audience", aud)
		case slices.Contains(cfg.ClientAudiences[:i], aud):
			return nil, fmt.Errorf("tokens: validator: client audience %q is repeated", aud)
		}
	}
	auds := append(slices.Clone(cfg.ClientAudiences), self)
	return &Validator{issuer: cfg.Issuer, self: self, audiences: auds, keys: keys, clock: clock}, nil
}

// Validate returns the claims of token, or one of the refusals above. It checks, in order:
//   - a compact JWS (so one signature) of at most 8 KiB, written in unpadded base64url, with only
//     alg, kid and typ in its protected header;
//   - typ at+jwt;
//   - a published kid, whose key can verify (else ErrKeyUnusable);
//   - the header's alg equal to that key's own (never none), so the token never chooses the alg;
//   - the signature, verified with the key's alg;
//   - every claim of TDD-04 §1 with its type: sub, jti and sid UUIDs, status active, suspended or
//     banned, no empty role or amr value; exp after iat, nbf not after exp, auth_time not after
//     iat + Leeway, and no roles in a restricted token;
//   - iss exactly;
//   - aud the self audience for a restricted status, a client's audience for an active one;
//   - exp, nbf and iat with Leeway against the clock: refused on or after exp + Leeway (RFC 7519
//     §4.1.4) and before nbf − Leeway or iat − Leeway.
//
// Signatures remain malleable within what jwx's decoder accepts (an ES256 signature has two valid
// forms), so nothing should key a cache, deny-list or rate limit on the token string or its hash:
// use Claims.ID (jti).
func (v *Validator) Validate(token string) (Claims, error) {
	pk, alg, err := v.key(token)
	if err != nil {
		return Claims{}, err
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
	if !slices.Contains(v.audiences, c.Audience) || c.Restricted != (c.Audience == v.self) {
		return Claims{}, ErrAudience
	}
	now := v.clock.Now()
	if !now.Before(c.ExpiresAt.Add(Leeway)) {
		return Claims{}, ErrExpired
	}
	if now.Before(c.NotBefore.Add(-Leeway)) || now.Before(c.IssuedAt.Add(-Leeway)) {
		return Claims{}, ErrNotYetValid
	}
	return c, nil
}

// key checks the token's form and protected header and returns the published key it names, with
// that key's alg, which the header's must equal.
func (v *Validator) key(token string) (app.PublicKey, jwa.SignatureAlgorithm, error) {
	var none jwa.SignatureAlgorithm
	if len(token) > maxTokenSize || !compactChars(token) {
		return app.PublicKey{}, none, ErrMalformed
	}
	msg, err := jws.Parse([]byte(token), jws.WithCompact())
	if err != nil {
		return app.PublicKey{}, none, ErrMalformed
	}
	h := msg.Signatures()[0].ProtectedHeaders()
	for _, k := range h.Keys() {
		if !slices.Contains(headerKeys, k) {
			return app.PublicKey{}, none, ErrMalformed
		}
	}
	if typ, ok := h.Type(); !ok || typ != TypeAccess {
		return app.PublicKey{}, none, ErrType
	}
	kid, _ := h.KeyID() // a missing kid is "", which no key has
	pk, ok := v.keys.Key(kid)
	if !ok {
		return app.PublicKey{}, none, ErrUnknownKey
	}
	keyAlg, ok := jwa.LookupSignatureAlgorithm(pk.Alg)
	if usable := keyTypes[pk.Alg]; !ok || usable == nil || !usable(pk.Key) {
		return app.PublicKey{}, none, fmt.Errorf("%w: alg %q with a %T", ErrKeyUnusable, pk.Alg, pk.Key)
	}
	// The key fixes the alg: none, a missing alg, or any alg other than the key's is refused here.
	if alg, ok := h.Algorithm(); !ok || alg != keyAlg {
		return app.PublicKey{}, none, ErrAlgorithm
	}
	return pk, keyAlg, nil
}

// compactChars reports whether token holds only base64url characters and dots, so a segment in
// padded or standard base64, which jwx's decoder would also accept, is refused.
func compactChars(token string) bool {
	for i := range len(token) {
		switch c := token[i]; {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// claimNames are the claims of TDD-04 §1; a token without any of them is refused.
var claimNames = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "sid", "client_id", "roles", "status", "amr", "auth_time"}

// parseClaims decodes the verified payload. Every claim of TDD-04 §1 must be present, non-null,
// of its type and consistent with the others; other claims are ignored.
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
	restricted := account.Restricted(status)
	switch {
	case errors.Join(err1, err2, err3, err4) != nil,
		status != account.StatusActive && !restricted,
		slices.Contains(p.Roles, ""), slices.Contains(p.AMR, ""),
		restricted && len(p.Roles) > 0,
		p.Exp <= p.Iat, p.Nbf > p.Exp, p.AuthTime > p.Iat+int64(Leeway/time.Second):
		return Claims{}, ErrClaims
	}
	return Claims{
		Issuer:     p.Iss,
		Subject:    sub,
		Audience:   p.Aud,
		ExpiresAt:  unix(p.Exp),
		IssuedAt:   unix(p.Iat),
		NotBefore:  unix(p.Nbf),
		ID:         jti,
		SessionID:  sid,
		ClientID:   p.ClientID,
		Roles:      p.Roles,
		Status:     status,
		AMR:        p.AMR,
		AuthTime:   unix(p.AuthTime),
		Restricted: restricted,
	}, nil
}

func unix(s int64) time.Time { return time.Unix(s, 0).UTC() }
