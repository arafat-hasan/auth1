package clientcreds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/domain"
)

// The form values of the grant (RFC 6749 §4.4, RFC 7523 §2.2).
const (
	GrantType     = "client_credentials"
	AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// The limits of TDD-05 §2.
const (
	maxAssertionSize = 8 << 10
	maxLifetime      = 5 * time.Minute  // exp − iat
	leeway           = 30 * time.Second // on iat and nbf, and past exp for the jti row
	maxJTI           = 256              // characters
)

// OAuthCode is an RFC 6749 §5.2 error code.
type OAuthCode string

// The codes the endpoint answers with.
const (
	InvalidRequest       OAuthCode = "invalid_request"
	InvalidClient        OAuthCode = "invalid_client"
	InvalidScope         OAuthCode = "invalid_scope"
	UnsupportedGrantType OAuthCode = "unsupported_grant_type"
)

// Error is a refusal answered with an RFC 6749 error. Only Code is sent.
type Error struct {
	Code OAuthCode
	// Reason says which check failed, for logs and tests. It is fixed text and never sent: every
	// invalid_client answers alike.
	Reason string
}

func (e *Error) Error() string { return "client credentials: " + string(e.Code) + ": " + e.Reason }

// Request is the token request's form.
type Request struct {
	GrantType     string
	AssertionType string
	Assertion     string
	Scope         *string // space-separated; nil when absent
}

// ServiceIssuer issues service tokens; tokens.Issuer implements it.
type ServiceIssuer interface {
	IssueService(clientID string, scopes []string) (tokens.Service, error)
}

// Options are the dependencies and the configuration of a Service.
type Options struct {
	Keys       app.ClientKeys
	Assertions app.ClientAssertions
	UnitOfWork app.UnitOfWork
	Issuer     ServiceIssuer
	Clock      app.Clock
	// Audiences are what an assertion's aud must contain one of: the token endpoint URL and the
	// issuer.
	Audiences []string
	// Clients maps each service client id to its configured scopes (its service_auth.callers
	// entry).
	Clients map[string][]string
	Logger  *slog.Logger
}

// Service is the client-credentials grant. Build it with New.
type Service struct{ o Options }

// New returns the grant, or an error naming what is missing.
func New(o Options) (*Service, error) {
	var missing []string
	for name, nilDep := range map[string]bool{
		"keys": o.Keys == nil, "assertions": o.Assertions == nil, "unit of work": o.UnitOfWork == nil,
		"issuer": o.Issuer == nil, "clock": o.Clock == nil, "logger": o.Logger == nil,
		"audiences": len(o.Audiences) == 0,
	} {
		if nilDep {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, fmt.Errorf("client credentials: missing %s", strings.Join(missing, ", "))
	}
	o.Clients = maps.Clone(o.Clients)
	o.Audiences = slices.Clone(o.Audiences)
	return &Service{o: o}, nil
}

// claims are the assertion's claims Issue reads. Times are NumericDates, possibly fractional.
type claims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Exp *json.Number    `json:"exp"`
	Iat *json.Number    `json:"iat"`
	Nbf *json.Number    `json:"nbf"`
	Jti *string         `json:"jti"`
}

// Issue checks r and returns a service token, in the order of TDD-05 §2: the form; the
// assertion's form and header; iss = sub = a configured client; its key, fetched outside any
// transaction; the signature with that key's alg; aud; the times; jti; the scope; and last the
// jti record, so a refused request never uses up an assertion. Every assertion failure is the same
// invalid_client. Keys that cannot be had, a store failure or no signing key are a
// *domain.Error UNAVAILABLE.
func (s *Service) Issue(ctx context.Context, r Request) (tokens.Service, error) {
	switch {
	case r.GrantType == "":
		return tokens.Service{}, &Error{Code: InvalidRequest, Reason: "no grant_type"}
	case r.GrantType != GrantType:
		return tokens.Service{}, &Error{Code: UnsupportedGrantType, Reason: "grant_type is not client_credentials"}
	case r.AssertionType != AssertionType:
		return tokens.Service{}, &Error{Code: InvalidRequest, Reason: "client_assertion_type is not jwt-bearer"}
	case r.Assertion == "":
		return tokens.Service{}, &Error{Code: InvalidRequest, Reason: "no client_assertion"}
	}

	client, c, err := s.verify(ctx, r.Assertion)
	if err != nil {
		return tokens.Service{}, s.refused(ctx, client, err)
	}
	scopes := grant(s.o.Clients[client], r.Scope)
	if len(scopes) == 0 {
		return tokens.Service{}, &Error{Code: InvalidScope, Reason: "no requested scope is configured for the client"}
	}
	var fresh bool
	err = s.o.UnitOfWork.Do(ctx, func(ctx context.Context) error {
		var err error
		fresh, err = s.o.Assertions.Record(ctx, client, *c.Jti, numeric(c.Exp).Add(leeway))
		return err
	})
	if err != nil {
		return tokens.Service{}, fmt.Errorf("record the assertion: %w", err)
	}
	if !fresh {
		return tokens.Service{}, s.refused(ctx, client, refusal("jti replayed"))
	}
	tok, err := s.o.Issuer.IssueService(client, scopes)
	if err != nil {
		return tokens.Service{}, fmt.Errorf("issue the service token: %w", err)
	}
	return tok, nil
}

// refusal is the reason an assertion is refused.
type refusal string

func (r refusal) Error() string { return string(r) }

// refused logs a refusal at debug level, with the fixed reason and a configured client id only
// (G-6), and returns it as invalid_client. Any other error passes through.
func (s *Service) refused(ctx context.Context, client string, err error) error {
	var r refusal
	if !errors.As(err, &r) {
		return err
	}
	if _, ok := s.o.Clients[client]; !ok {
		client = "unknown"
	}
	s.o.Logger.LogAttrs(ctx, slog.LevelDebug, "client assertion refused",
		slog.String("client", client), slog.String("reason", string(r)))
	return &Error{Code: InvalidClient, Reason: string(r)}
}

// headerKeys are the protected header parameters an assertion may have.
var headerKeys = []string{jws.AlgorithmKey, jws.KeyIDKey, jws.TypeKey}

// verify checks the assertion up to and including jti, and returns the client and the claims. A
// refusal is a refusal; the client is "" until iss = sub is a configured client.
func (s *Service) verify(ctx context.Context, assertion string) (string, claims, error) {
	if len(assertion) > maxAssertionSize || !compactChars(assertion) {
		return "", claims{}, refusal("not a compact JWS of at most 8 KiB")
	}
	msg, err := jws.Parse([]byte(assertion), jws.WithCompact())
	if err != nil {
		return "", claims{}, refusal("not a compact JWS of at most 8 KiB")
	}
	h := msg.Signatures()[0].ProtectedHeaders()
	for _, k := range h.Keys() {
		if !slices.Contains(headerKeys, k) {
			return "", claims{}, refusal("a header parameter other than alg, kid and typ")
		}
	}
	alg, _ := h.Algorithm()
	if alg != jwa.RS256() && alg != jwa.ES256() {
		return "", claims{}, refusal("alg is not RS256 or ES256")
	}
	kid, _ := h.KeyID()
	if kid == "" {
		return "", claims{}, refusal("no kid")
	}
	if typ, ok := h.Type(); ok && typ != "JWT" && typ != "client-authentication+jwt" {
		return "", claims{}, refusal("typ is not JWT or client-authentication+jwt")
	}

	unverified, err := decode(msg.Payload())
	if err != nil {
		return "", claims{}, err
	}
	client := unverified.Iss
	if _, ok := s.o.Clients[client]; !ok || client != unverified.Sub {
		return "", claims{}, refusal("iss and sub are not one configured client")
	}

	pk, err := s.o.Keys.Key(ctx, client, kid)
	switch {
	case errors.Is(err, app.ErrUnknownClientKey):
		return client, claims{}, refusal("no such kid for the client")
	case errors.Is(err, app.ErrClientKeysUnavailable):
		return client, claims{}, fmt.Errorf("client keys: %w", &domain.Error{
			Code: domain.CodeUnavailable, Detail: "The client's keys are not available.", RetryAfter: time.Second,
		})
	case err != nil:
		return client, claims{}, fmt.Errorf("client keys: %w", err)
	}
	if pk.Alg != alg.String() {
		return client, claims{}, refusal("alg is not the key's")
	}
	body, err := jws.Verify([]byte(assertion), jws.WithCompact(), jws.WithKey(alg, pk.Key))
	if err != nil {
		return client, claims{}, refusal("bad signature")
	}
	c, err := decode(body)
	if err != nil {
		return client, claims{}, err
	}
	if err := s.check(c); err != nil {
		return client, claims{}, err
	}
	return client, c, nil
}

// check applies the claim checks after the signature: aud, the times and jti.
func (s *Service) check(c claims) error {
	if !audience(c.Aud, s.o.Audiences) {
		return refusal("aud is not the token endpoint or the issuer")
	}
	if c.Exp == nil || c.Iat == nil || !valid(c.Exp) || !valid(c.Iat) || (c.Nbf != nil && !valid(c.Nbf)) {
		return refusal("exp or iat missing, or a time that is not a number")
	}
	now := s.o.Clock.Now()
	exp, iat := numeric(c.Exp), numeric(c.Iat)
	switch {
	case !now.Before(exp):
		return refusal("expired")
	case iat.After(now.Add(leeway)):
		return refusal("iat in the future")
	case exp.Sub(iat) > maxLifetime:
		return refusal("exp more than 5 minutes after iat")
	case c.Nbf != nil && numeric(c.Nbf).After(now.Add(leeway)):
		return refusal("nbf in the future")
	}
	if c.Jti == nil || *c.Jti == "" || utf8.RuneCountInString(*c.Jti) > maxJTI {
		return refusal("jti missing or over 256 characters")
	}
	return nil
}

// decode decodes a payload into claims; a payload that is not a JSON object of these types is a
// refusal.
func decode(payload []byte) (claims, error) {
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	var c claims
	if err := d.Decode(&c); err != nil {
		return claims{}, refusal("claims are not a JSON object of the expected types")
	}
	return c, nil
}

// audience reports whether aud, a string or an array of strings, holds one of want.
func audience(aud json.RawMessage, want []string) bool {
	var one string
	if json.Unmarshal(aud, &one) == nil {
		return slices.Contains(want, one)
	}
	var many []string
	if json.Unmarshal(aud, &many) == nil {
		return slices.ContainsFunc(many, func(a string) bool { return slices.Contains(want, a) })
	}
	return false
}

// valid reports whether n is a finite NumericDate a time.Time holds.
func valid(n *json.Number) bool {
	f, err := n.Float64()
	return err == nil && !math.IsInf(f, 0) && !math.IsNaN(f) && math.Abs(f) < 1e12
}

// numeric returns NumericDate n as a time; valid(n) holds.
func numeric(n *json.Number) time.Time {
	f, _ := n.Float64()
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC()
}

// grant returns the requested scopes the client has, in configured order, each once; with none
// requested, every configured scope (TDD-05 §2).
func grant(configured []string, requested *string) []string {
	var want []string
	if requested != nil {
		want = strings.Fields(*requested)
	}
	if len(want) == 0 {
		return slices.Clone(configured)
	}
	var out []string
	for _, s := range configured {
		if slices.Contains(want, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// compactChars reports whether s holds only base64url characters and dots, so a segment in
// padded or standard base64, which jwx's decoder would also accept, is refused.
func compactChars(s string) bool {
	for i := range len(s) {
		switch c := s[i]; {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}
