package tokens_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

func TestValidateRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		status   account.Status
		es256    bool
		audience string
		roles    []string
	}{
		{name: "full RS256", status: account.StatusActive, audience: appAudience, roles: []string{"a", "b"}},
		{name: "full ES256", status: account.StatusActive, es256: true, audience: appAudience, roles: []string{"a", "b"}},
		{name: "restricted RS256", status: account.StatusSuspended, audience: selfAudience, roles: []string{}},
		{name: "restricted ES256", status: account.StatusBanned, es256: true, audience: selfAudience, roles: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(config())
			if tt.es256 {
				_, ecKid := e.keys.Kids()
				e.keys.SetActive(ecKid)
			}
			issued, err := e.iss.IssueAccess(session(), acct(tt.status), client())
			if err != nil {
				t.Fatal(err)
			}

			got, err := e.val.Validate(issued.Token)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			iat := time.Unix(now.Unix(), 0).UTC()
			want := tokens.Claims{
				Issuer:     issuer,
				Subject:    accountID,
				Audience:   tt.audience,
				ExpiresAt:  iat.Add(15 * time.Minute),
				IssuedAt:   iat,
				NotBefore:  iat,
				ID:         fakes.ID(1),
				SessionID:  sessionID,
				ClientID:   "web",
				Roles:      tt.roles,
				Status:     tt.status,
				AMR:        []string{"pwd", "otp", "mfa"},
				AuthTime:   authTime,
				Restricted: account.Restricted(tt.status),
			}
			if d := cmp.Diff(want, got); d != "" {
				t.Errorf("Claims (-want +got):\n%s", d)
			}
		})
	}
}

func TestValidateRestrictedWithDefaultSelfAudience(t *testing.T) {
	t.Parallel()
	cfg := config()
	cfg.SelfAudience = ""
	e := newEnv(cfg)
	issued, err := e.iss.IssueAccess(session(), acct(account.StatusSuspended), client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.val.Validate(issued.Token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.Audience != issuer || !got.Restricted {
		t.Errorf("aud %q, restricted %v; want the issuer, true", got.Audience, got.Restricted)
	}
}

func TestValidateEveryClientAudience(t *testing.T) {
	t.Parallel()
	for _, aud := range config().ClientAudiences {
		t.Run(aud, func(t *testing.T) {
			t.Parallel()
			e := newEnv(config())
			s := session()
			s.ClientID = "c"
			issued, err := e.iss.IssueAccess(s, acct(account.StatusActive), tokens.Client{ID: "c", Audience: aud})
			if err != nil {
				t.Fatal(err)
			}
			if got, err := e.val.Validate(issued.Token); err != nil || got.Audience != aud {
				t.Errorf("Validate: aud %q, err %v; want %q", got.Audience, err, aud)
			}
		})
	}
}

func TestValidateAtMaxSize(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	tok := ofLength(t, e, 8<<10)
	if _, err := e.val.Validate(tok); err != nil {
		t.Errorf("a token of exactly 8 KiB: %v", err)
	}
}

// stubKeys publishes one key with a chosen alg and public key.
type stubKeys struct{ pk app.PublicKey }

func (s stubKeys) Key(kid string) (app.PublicKey, bool) { return s.pk, kid == s.pk.Kid }

func (s stubKeys) Published() ([]app.PublicKey, bool) { return []app.PublicKey{s.pk}, true }

// TestValidateUnusableKey: a published key that cannot verify is a keyring fault, not a bad
// token, so its error does not match ErrInvalid.
func TestValidateUnusableKey(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	rsaKid, ecKid := e.keys.Kids()
	tok := validToken(t, e)
	ecPub := e.keys.Private(ecKid).Public()
	rsaPub := e.keys.Private(rsaKid).Public()
	tests := []struct {
		name string
		pk   app.PublicKey
	}{
		{name: "unknown alg", pk: app.PublicKey{Kid: rsaKid, Alg: "XX999", Key: rsaPub}},
		{name: "EC key under RS256", pk: app.PublicKey{Kid: rsaKid, Alg: "RS256", Key: ecPub}},
		{name: "RSA key under ES256", pk: app.PublicKey{Kid: rsaKid, Alg: "ES256", Key: rsaPub}},
		{name: "no key", pk: app.PublicKey{Kid: rsaKid, Alg: "RS256"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, err := tokens.NewValidator(config(), stubKeys{tt.pk}, e.clock)
			if err != nil {
				t.Fatal(err)
			}
			_, err = v.Validate(tok)
			if !errors.Is(err, tokens.ErrKeyUnusable) || errors.Is(err, tokens.ErrInvalid) {
				t.Errorf("err = %v; want ErrKeyUnusable, not ErrInvalid", err)
			}
		})
	}
}

func TestNewValidatorRefusesConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		change func(*tokens.Config)
	}{
		{name: "no issuer", change: func(c *tokens.Config) { c.Issuer = ""; c.SelfAudience = "" }},
		{name: "empty client audience", change: func(c *tokens.Config) { c.ClientAudiences = []string{appAudience, ""} }},
		{name: "duplicate client audience", change: func(c *tokens.Config) { c.ClientAudiences = []string{appAudience, appAudience} }},
		{name: "client audience is the self audience", change: func(c *tokens.Config) { c.ClientAudiences = []string{selfAudience} }},
		{name: "client audience is the default self audience", change: func(c *tokens.Config) {
			c.SelfAudience = ""
			c.ClientAudiences = []string{issuer}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := config()
			tt.change(&cfg)
			if v, err := tokens.NewValidator(cfg, fakes.NewKeys(), fakes.NewClock(now)); err == nil || v != nil {
				t.Errorf("NewValidator = %v, %v; want an error", v, err)
			}
		})
	}
}

// refusal is one token Validate must refuse, with the refusal it must give.
type refusal struct {
	name  string
	token func(t *testing.T, e *env) string
	clock func(e *env) // moves the clock before Validate; nil: leave it at now
	want  error
}

// refusals is one row per refusal. Each changes one thing from a valid token.
func refusals() []refusal {
	at := func(t *testing.T, e *env, claims map[string]any) string {
		rsaKid, _ := e.keys.Kids()
		return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"kid": rsaKid, "typ": "at+jwt"}, claims)
	}
	changed := func(changes map[string]any) func(*testing.T, *env) string {
		return func(t *testing.T, e *env) string { return at(t, e, with(validClaims(t, e), changes)) }
	}
	valid := changed(nil)
	expAt := func(e *env, d time.Duration) {
		e.clock.Set(time.Unix(now.Unix(), 0).Add(15*time.Minute + d))
	}

	rows := []refusal{
		{
			name: "alg none",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				return unsigned(t, map[string]any{"alg": "none", "kid": rsaKid, "typ": "at+jwt"}, validClaims(t, e))
			},
			want: tokens.ErrAlgorithm,
		},
		{
			name: "alg other than the JWK's, same key",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				return sign(t, jwa.RS384(), e.keys.Private(rsaKid), map[string]any{"kid": rsaKid, "typ": "at+jwt"}, validClaims(t, e))
			},
			want: tokens.ErrAlgorithm,
		},
		{
			name: "alg other than the JWK's, other key",
			token: func(t *testing.T, e *env) string {
				rsaKid, ecKid := e.keys.Kids()
				return sign(t, jwa.ES256(), e.keys.Private(ecKid), map[string]any{"kid": rsaKid, "typ": "at+jwt"}, validClaims(t, e))
			},
			want: tokens.ErrAlgorithm,
		},
		{
			name: "alg HS256 with the public key as secret",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				return sign(t, jwa.HS256(), rsaPublicDER(t, e), map[string]any{"kid": rsaKid, "typ": "at+jwt"}, validClaims(t, e))
			},
			want: tokens.ErrAlgorithm,
		},
		{
			name: "typ JWT",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"kid": rsaKid, "typ": "JWT"}, validClaims(t, e))
			},
			want: tokens.ErrType,
		},
		{
			name: "typ application/at+jwt",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"kid": rsaKid, "typ": "application/at+jwt"}, validClaims(t, e))
			},
			want: tokens.ErrType,
		},
		{
			name: "typ missing",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"kid": rsaKid}, validClaims(t, e))
			},
			want: tokens.ErrType,
		},
		{name: "wrong issuer", token: changed(map[string]any{"iss": issuer + "/"}), want: tokens.ErrIssuer},
		{name: "expired beyond leeway", token: valid, clock: func(e *env) { expAt(e, 31*time.Second) }, want: tokens.ErrExpired},
		{
			name:  "nbf beyond leeway",
			token: changed(map[string]any{"nbf": now.Unix() + 60}),
			want:  tokens.ErrNotYetValid,
		},
		{
			name:  "iat beyond leeway",
			token: changed(map[string]any{"iat": now.Unix() + 60}),
			want:  tokens.ErrNotYetValid,
		},
		{
			name: "unknown kid",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"kid": "nope", "typ": "at+jwt"}, validClaims(t, e))
			},
			want: tokens.ErrUnknownKey,
		},
		{
			name: "kid missing",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"typ": "at+jwt"}, validClaims(t, e))
			},
			want: tokens.ErrUnknownKey,
		},
		{
			name: "kid unpublished after signing",
			token: func(t *testing.T, e *env) string {
				tok := valid(t, e)
				rsaKid, _ := e.keys.Kids()
				e.keys.Unpublish(rsaKid)
				return tok
			},
			want: tokens.ErrUnknownKey,
		},
		{
			name: "tampered payload",
			token: func(t *testing.T, e *env) string {
				good := strings.Split(valid(t, e), ".")
				other := strings.Split(changed(map[string]any{"roles": []string{"a", "b", "c"}})(t, e), ".")
				return good[0] + "." + other[1] + "." + good[2]
			},
			want: tokens.ErrSignature,
		},
		{name: "audience not accepted", token: changed(map[string]any{"aud": "https://evil.example.com"}), want: tokens.ErrAudience},
		{name: "audience as an array", token: changed(map[string]any{"aud": []string{appAudience}}), want: tokens.ErrClaims},
		{name: "sub not a uuid", token: changed(map[string]any{"sub": "someone"}), want: tokens.ErrClaims},
		{name: "jti not a uuid", token: changed(map[string]any{"jti": "x"}), want: tokens.ErrClaims},
		{name: "sid not a uuid", token: changed(map[string]any{"sid": "x"}), want: tokens.ErrClaims},
		{name: "role empty", token: changed(map[string]any{"roles": []any{"a", ""}}), want: tokens.ErrClaims},
		{name: "role null", token: changed(map[string]any{"roles": []any{"a", nil}}), want: tokens.ErrClaims},
		{name: "amr element empty", token: changed(map[string]any{"amr": []any{"pwd", ""}}), want: tokens.ErrClaims},
		{name: "exp before iat", token: changed(map[string]any{"exp": now.Unix() - 1}), want: tokens.ErrClaims},
		{name: "exp at iat", token: changed(map[string]any{"exp": now.Unix()}), want: tokens.ErrClaims},
		{name: "nbf after exp", token: changed(map[string]any{"nbf": now.Unix() + 16*60}), want: tokens.ErrClaims},
		{name: "auth_time after iat", token: changed(map[string]any{"auth_time": now.Unix() + 31}), want: tokens.ErrClaims},
		{
			name:  "restricted status with a client audience",
			token: changed(map[string]any{"status": "suspended", "roles": []any{}}),
			want:  tokens.ErrAudience,
		},
		{name: "active status with the self audience", token: changed(map[string]any{"aud": selfAudience}), want: tokens.ErrAudience},
		{
			name:  "restricted status with roles",
			token: changed(map[string]any{"status": "banned", "aud": selfAudience}),
			want:  tokens.ErrClaims,
		},
		{name: "exp a string", token: changed(map[string]any{"exp": "soon"}), want: tokens.ErrClaims},
		{name: "exp a fraction", token: changed(map[string]any{"exp": 1.5}), want: tokens.ErrClaims},
		{name: "roles a string", token: changed(map[string]any{"roles": "a"}), want: tokens.ErrClaims},
		{name: "roles null", token: changed(map[string]any{"roles": json.RawMessage("null")}), want: tokens.ErrClaims},
		{name: "status unknown", token: changed(map[string]any{"status": "frozen"}), want: tokens.ErrClaims},
		{name: "status deleted", token: changed(map[string]any{"status": "deleted"}), want: tokens.ErrClaims},
		{
			name: "JSON serialisation",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"kid": rsaKid, "typ": "at+jwt"}, validClaims(t, e), jws.WithJSON())
			},
			want: tokens.ErrMalformed,
		},
		{
			name: "extra header jku",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"kid": rsaKid, "typ": "at+jwt", "jku": "https://evil.example.com/jwks"}, validClaims(t, e))
			},
			want: tokens.ErrMalformed,
		},
		{name: "garbage", token: func(*testing.T, *env) string { return "not.a.token" }, want: tokens.ErrMalformed},
		{name: "empty", token: func(*testing.T, *env) string { return "" }, want: tokens.ErrMalformed},
		{name: "over 8 KiB", token: changed(map[string]any{"pad": strings.Repeat("x", 8<<10)}), want: tokens.ErrMalformed},
		{name: "8 KiB + 1", token: func(t *testing.T, e *env) string { return ofLength(t, e, 8<<10+1) }, want: tokens.ErrMalformed},
		{name: "padded signature", token: func(t *testing.T, e *env) string { return valid(t, e) + "==" }, want: tokens.ErrMalformed},
		{
			name: "standard base64 character",
			token: func(t *testing.T, e *env) string {
				parts := strings.Split(valid(t, e), ".")
				return parts[0] + "." + parts[1] + "." + strings.NewReplacer("-", "+", "_", "/").Replace(parts[2]) + "+"
			},
			want: tokens.ErrMalformed,
		},
		{
			name: "alg missing",
			token: func(t *testing.T, e *env) string {
				rsaKid, _ := e.keys.Kids()
				sig := strings.Split(valid(t, e), ".")[2]
				return unsigned(t, map[string]any{"kid": rsaKid, "typ": "at+jwt"}, validClaims(t, e)) + sig
			},
			want: tokens.ErrAlgorithm,
		},
		{
			name: "alg other than the EC JWK's",
			token: func(t *testing.T, e *env) string {
				rsaKid, ecKid := e.keys.Kids()
				return sign(t, jwa.RS256(), e.keys.Private(rsaKid), map[string]any{"kid": ecKid, "typ": "at+jwt"}, validClaims(t, e))
			},
			want: tokens.ErrAlgorithm,
		},
		{
			name: "keyring not synced",
			token: func(t *testing.T, e *env) string {
				tok := valid(t, e)
				e.keys.Unsynced()
				return tok
			},
			want: tokens.ErrUnknownKey,
		},
	}
	for _, name := range []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "sid", "client_id", "roles", "status", "amr", "auth_time"} {
		rows = append(rows, refusal{name: name + " missing", token: changed(map[string]any{name: nil}), want: tokens.ErrClaims})
	}
	return rows
}

func TestValidateRefusals(t *testing.T) {
	t.Parallel()
	for _, tt := range refusals() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(config())
			tok := tt.token(t, e)
			if tt.clock != nil {
				tt.clock(e)
			}
			got, err := e.val.Validate(tok)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if !errors.Is(err, tokens.ErrInvalid) {
				t.Errorf("err = %v does not match ErrInvalid", err)
			}
			if d := cmp.Diff(tokens.Claims{}, got); d != "" {
				t.Errorf("claims alongside a refusal (-want +got):\n%s", d)
			}
		})
	}
}

func TestValidateLeeway(t *testing.T) {
	t.Parallel()
	iat := time.Unix(now.Unix(), 0).UTC()
	exp := iat.Add(15 * time.Minute)
	tests := []struct {
		name string
		at   time.Time
		want error
	}{
		// Not accepted on or after exp + Leeway (RFC 7519 §4.1.4), nor before nbf - Leeway.
		{name: "exp + 29s", at: exp.Add(29 * time.Second)},
		{name: "exp + 30s - 1µs", at: exp.Add(30*time.Second - time.Microsecond)},
		{name: "exp + 30s", at: exp.Add(30 * time.Second), want: tokens.ErrExpired},
		{name: "exp + 31s", at: exp.Add(31 * time.Second), want: tokens.ErrExpired},
		{name: "nbf - 29s", at: iat.Add(-29 * time.Second)},
		{name: "nbf - 30s", at: iat.Add(-30 * time.Second)},
		{name: "nbf - 30s - 1µs", at: iat.Add(-30*time.Second - time.Microsecond), want: tokens.ErrNotYetValid},
		{name: "nbf - 31s", at: iat.Add(-31 * time.Second), want: tokens.ErrNotYetValid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(config())
			issued, err := e.iss.IssueAccess(session(), acct(account.StatusActive), client())
			if err != nil {
				t.Fatal(err)
			}
			e.clock.Set(tt.at)
			if _, err := e.val.Validate(issued.Token); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestValidateErrorsDoNotEchoToken(t *testing.T) {
	t.Parallel()
	for _, tt := range refusals() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(config())
			tok := tt.token(t, e)
			if tt.clock != nil {
				tt.clock(e)
			}
			_, err := e.val.Validate(tok)
			if err == nil {
				t.Fatal("no error")
			}
			rsaKid, ecKid := e.keys.Kids()
			msg := err.Error()
			secrets := []string{rsaKid, ecKid, accountID.String(), sessionID.String(), fakes.ID(1).String(), "example.com", "web"}
			if len(tok) > 8 {
				secrets = append(secrets, tok, tok[:8])
			}
			for _, s := range secrets {
				if strings.Contains(msg, s) {
					t.Errorf("error %q holds %q", msg, s)
				}
			}
		})
	}
}

func FuzzValidate(f *testing.F) {
	e := newEnv(config())
	issued, err := e.iss.IssueAccess(session(), acct(account.StatusActive), client())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(issued.Token)
	f.Add("")
	f.Add("..")
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Fuzz(func(t *testing.T, tok string) {
		_, err := e.val.Validate(tok)
		if err != nil && !errors.Is(err, tokens.ErrInvalid) {
			t.Errorf("err = %v does not match ErrInvalid", err)
		}
	})
}
