package tokens_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

var serviceScopes = []string{"tokens:introspect", "directory:read"}

func TestIssueServiceClaims(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	got, err := e.iss.IssueService("reports", serviceScopes)
	if err != nil {
		t.Fatal(err)
	}
	header, claims := decode(t, got.Token)
	rsaKid, _ := e.keys.Kids()
	if d := cmp.Diff(map[string]any{"alg": "RS256", "kid": rsaKid, "typ": "at+jwt"}, header); d != "" {
		t.Errorf("header (-want +got):\n%s", d)
	}
	iat := time.Unix(now.Unix(), 0).UTC()
	want := map[string]any{
		"iss": issuer, "sub": "reports", "aud": serviceAud,
		"exp": num(iat.Add(5 * time.Minute)), "iat": num(iat), "nbf": num(iat),
		"jti": fakes.ID(1).String(), "client_id": "reports", "scope": "tokens:introspect directory:read",
	}
	if d := cmp.Diff(want, claims); d != "" {
		t.Errorf("claims (-want +got):\n%s", d)
	}
	wantSvc := tokens.Service{Token: got.Token, ID: fakes.ID(1), ExpiresAt: iat.Add(5 * time.Minute), Scopes: serviceScopes}
	if d := cmp.Diff(wantSvc, got); d != "" {
		t.Errorf("Service (-want +got):\n%s", d)
	}
}

func TestIssueServiceRefuses(t *testing.T) {
	t.Parallel()
	noAudience := config()
	noAudience.ServiceAudience = ""
	tests := []struct {
		name   string
		cfg    tokens.Config
		client string
		scopes []string
	}{
		{name: "no client", cfg: config(), scopes: serviceScopes},
		{name: "no scope", cfg: config(), client: "reports"},
		{name: "empty scope", cfg: config(), client: "reports", scopes: []string{"a", ""}},
		{name: "scope with a space", cfg: config(), client: "reports", scopes: []string{"a b"}},
		{name: "no service audience", cfg: noAudience, client: "reports", scopes: serviceScopes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(tt.cfg)
			if got, err := e.iss.IssueService(tt.client, tt.scopes); !errors.Is(err, tokens.ErrNotIssuable) || got.Token != "" {
				t.Errorf("IssueService = %v, %v; want ErrNotIssuable", got, err)
			}
		})
	}
}

func TestIssueServiceNoSigningKey(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	e.keys.NoSigner()
	if _, err := e.iss.IssueService("reports", serviceScopes); !errors.Is(err, app.ErrNoSigningKey) {
		t.Errorf("err = %v, want ErrNoSigningKey", err)
	}
}

func TestValidateServiceRoundTrip(t *testing.T) {
	t.Parallel()
	for _, es256 := range []bool{false, true} {
		t.Run(fmt.Sprint("es256=", es256), func(t *testing.T) {
			t.Parallel()
			e := newEnv(config())
			if es256 {
				_, ecKid := e.keys.Kids()
				e.keys.SetActive(ecKid)
			}
			issued, err := e.iss.IssueService("reports", serviceScopes)
			if err != nil {
				t.Fatal(err)
			}
			got, err := e.val.ValidateService(issued.Token)
			if err != nil {
				t.Fatalf("ValidateService: %v", err)
			}
			iat := time.Unix(now.Unix(), 0).UTC()
			want := tokens.ServiceClaims{
				Issuer: issuer, ClientID: "reports", Audience: serviceAud,
				ExpiresAt: iat.Add(5 * time.Minute), IssuedAt: iat, NotBefore: iat,
				ID: fakes.ID(1), Scopes: serviceScopes,
			}
			if d := cmp.Diff(want, got); d != "" {
				t.Errorf("claims (-want +got):\n%s", d)
			}
		})
	}
}

// TestValidateRefusesServiceToken: a service token is never accepted where a user's is (SDD
// D-13), so a user endpoint refuses it.
func TestValidateRefusesServiceToken(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	issued, err := e.iss.IssueService("reports", serviceScopes)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e.val.Validate(issued.Token); !errors.Is(err, tokens.ErrInvalid) {
		t.Errorf("Validate = %v, %v; want a refusal", got, err)
	}
}

// TestValidateRefusesServiceShapedTokenOnClientAudience: a token of the service claim set is
// refused by Validate even with a client's audience, so the claim sets alone keep them apart.
func TestValidateRefusesServiceShapedTokenOnClientAudience(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	tok := signService(t, e, with(serviceClaims(t, e), map[string]any{"aud": appAudience}))
	if _, err := e.val.Validate(tok); !errors.Is(err, tokens.ErrClaims) {
		t.Errorf("err = %v, want ErrClaims", err)
	}
}

// TestValidateServiceRefusesUserToken: a user token, full or restricted, is never accepted on a
// service endpoint (SDD D-13).
func TestValidateServiceRefusesUserToken(t *testing.T) {
	t.Parallel()
	for _, status := range []account.Status{account.StatusActive, account.StatusSuspended} {
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()
			e := newEnv(config())
			issued, err := e.iss.IssueAccess(session(), acct(status), client())
			if err != nil {
				t.Fatal(err)
			}
			if got, err := e.val.ValidateService(issued.Token); !errors.Is(err, tokens.ErrInvalid) {
				t.Errorf("ValidateService = %v, %v; want a refusal", got, err)
			}
		})
	}
}

// TestValidateServiceRefusesUserShapedTokenOnServiceAudience: a token of the user claim set is
// refused by ValidateService even with the service audience.
func TestValidateServiceRefusesUserShapedTokenOnServiceAudience(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	tok := signService(t, e, with(validClaims(t, e), map[string]any{"aud": serviceAud}))
	if _, err := e.val.ValidateService(tok); !errors.Is(err, tokens.ErrClaims) {
		t.Errorf("err = %v, want ErrClaims", err)
	}
}

// serviceClaims returns the claims of a service token that e issues, as decoded JSON values.
func serviceClaims(t *testing.T, e *env) map[string]any {
	t.Helper()
	got, err := e.iss.IssueService("reports", serviceScopes)
	if err != nil {
		t.Fatal(err)
	}
	_, claims := decode(t, got.Token)
	return claims
}

// signService signs claims with e's RSA key as an access token.
func signService(t *testing.T, e *env, claims map[string]any) string {
	t.Helper()
	rsaKid, _ := e.keys.Kids()
	return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"kid": rsaKid, "typ": "at+jwt"}, claims)
}

func TestValidateServiceRefusals(t *testing.T) {
	t.Parallel()
	changed := func(changes map[string]any) func(*testing.T, *env) string {
		return func(t *testing.T, e *env) string { return signService(t, e, with(serviceClaims(t, e), changes)) }
	}
	iat := time.Unix(now.Unix(), 0)
	tests := []refusal{
		{name: "typ JWT", want: tokens.ErrType, token: func(t *testing.T, e *env) string {
			rsaKid, _ := e.keys.Kids()
			return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"kid": rsaKid, "typ": "JWT"}, serviceClaims(t, e))
		}},
		{name: "signed by another key under the kid", want: tokens.ErrSignature, token: func(t *testing.T, e *env) string {
			rsaKid, _ := e.keys.Kids()
			other, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return sign(t, jwa.RS256(), other, map[string]any{"kid": rsaKid, "typ": "at+jwt"}, serviceClaims(t, e))
		}},
		{name: "alg none", want: tokens.ErrAlgorithm, token: func(t *testing.T, e *env) string {
			rsaKid, _ := e.keys.Kids()
			return unsigned(t, map[string]any{"alg": "none", "kid": rsaKid, "typ": "at+jwt"}, serviceClaims(t, e))
		}},
		{name: "wrong issuer", want: tokens.ErrIssuer, token: changed(map[string]any{"iss": "https://other.example.com"})},
		{name: "client audience", want: tokens.ErrAudience, token: changed(map[string]any{"aud": appAudience})},
		{name: "self audience", want: tokens.ErrAudience, token: changed(map[string]any{"aud": selfAudience})},
		{name: "audience array", want: tokens.ErrClaims, token: changed(map[string]any{"aud": []string{serviceAud}})},
		{name: "extra claim", want: tokens.ErrClaims, token: changed(map[string]any{"sid": sessionID.String()})},
		{name: "sub not client_id", want: tokens.ErrClaims, token: changed(map[string]any{"sub": "billing"})},
		{name: "empty client_id", want: tokens.ErrClaims, token: changed(map[string]any{"sub": "", "client_id": ""})},
		{name: "no scope", want: tokens.ErrClaims, token: changed(map[string]any{"scope": nil})},
		{name: "empty scope", want: tokens.ErrClaims, token: changed(map[string]any{"scope": ""})},
		{name: "double space in scope", want: tokens.ErrClaims, token: changed(map[string]any{"scope": "a  b"})},
		{name: "jti not a UUID", want: tokens.ErrClaims, token: changed(map[string]any{"jti": "x"})},
		{name: "no exp", want: tokens.ErrClaims, token: changed(map[string]any{"exp": nil})},
		{name: "exp before iat", want: tokens.ErrClaims, token: changed(map[string]any{"exp": iat.Unix() - 1})},
		{name: "expired", want: tokens.ErrExpired, token: changed(nil), clock: func(e *env) {
			e.clock.Set(iat.Add(5*time.Minute + tokens.Leeway))
		}},
		{name: "not yet valid", want: tokens.ErrNotYetValid, token: changed(nil), clock: func(e *env) {
			e.clock.Set(iat.Add(-tokens.Leeway - time.Second))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(config())
			tok := tt.token(t, e)
			if tt.clock != nil {
				tt.clock(e)
			}
			got, err := e.val.ValidateService(tok)
			if !errors.Is(err, tt.want) || !errors.Is(err, tokens.ErrInvalid) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if d := cmp.Diff(tokens.ServiceClaims{}, got); d != "" {
				t.Errorf("claims alongside a refusal (-want +got):\n%s", d)
			}
		})
	}
}

// TestValidateServiceWithoutServiceAudience: a validator built without a service audience
// accepts no service token.
func TestValidateServiceWithoutServiceAudience(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	issued, err := e.iss.IssueService("reports", serviceScopes)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config()
	cfg.ServiceAudience = ""
	val, err := tokens.NewValidator(cfg, e.keys, e.clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := val.ValidateService(issued.Token); !errors.Is(err, tokens.ErrAudience) {
		t.Errorf("err = %v, want ErrAudience", err)
	}
}

func TestNewValidatorRefusesServiceAudience(t *testing.T) {
	t.Parallel()
	for name, aud := range map[string]string{"a client's": appAudience, "the self audience": selfAudience} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := config()
			cfg.ServiceAudience = aud
			if v, err := tokens.NewValidator(cfg, fakes.NewKeys(), fakes.NewClock(now)); err == nil || v != nil {
				t.Errorf("NewValidator = %v, %v; want an error", v, err)
			}
		})
	}
}

func TestNewIssuerRefusesServiceTTL(t *testing.T) {
	t.Parallel()
	cfg := config()
	cfg.ServiceTTL = 0
	if i, err := tokens.NewIssuer(cfg, fakes.NewKeys(), fakes.NewClock(now), fakes.NewIDs()); err == nil || i != nil {
		t.Errorf("NewIssuer = %v, %v; want an error", i, err)
	}
}

// TestServiceRedactsToken: a Service printed or logged never shows its token.
func TestServiceRedactsToken(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	got, err := e.iss.IssueService("reports", serviceScopes)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("issued", "service", got)
	js, _ := json.Marshal(got)
	outs := map[string]string{
		"%v": fmt.Sprintf("%v", got), "%+v": fmt.Sprintf("%+v", got), "%#v": fmt.Sprintf("%#v", got),
		"%s": fmt.Sprintf("%s", got), "pointer": fmt.Sprintf("%v", &got), "slog": log.String(), "json": string(js),
	}
	sig := got.Token[strings.LastIndexByte(got.Token, '.')+1:]
	for name, out := range outs {
		if strings.Contains(out, sig) || strings.Contains(out, got.Token[:20]) {
			t.Errorf("%s shows the token: %s", name, out)
		}
	}
}
