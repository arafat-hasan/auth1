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
				Issuer:    issuer,
				Subject:   accountID,
				Audience:  tt.audience,
				ExpiresAt: iat.Add(15 * time.Minute),
				IssuedAt:  iat,
				NotBefore: iat,
				ID:        fakes.ID(1),
				SessionID: sessionID,
				ClientID:  "web",
				Roles:     tt.roles,
				Status:    tt.status,
				AMR:       []string{"pwd", "otp", "mfa"},
				AuthTime:  authTime,
			}
			if d := cmp.Diff(want, got); d != "" {
				t.Errorf("Claims (-want +got):\n%s", d)
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
		{name: "exp + 29s", at: exp.Add(29 * time.Second)},
		{name: "exp + 30s", at: exp.Add(30 * time.Second)},
		{name: "exp + 30s + 1µs", at: exp.Add(30*time.Second + time.Microsecond), want: tokens.ErrExpired},
		{name: "exp + 31s", at: exp.Add(31 * time.Second), want: tokens.ErrExpired},
		{name: "nbf - 29s", at: iat.Add(-29 * time.Second)},
		{name: "nbf - 30s", at: iat.Add(-30 * time.Second)},
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
