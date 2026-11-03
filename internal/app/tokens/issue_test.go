package tokens_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// The golden tests compare the whole header and claim set: an extra or a missing claim fails.

func TestIssueAccessFullClaims(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	rsaKid, _ := e.keys.Kids()

	got, err := e.iss.IssueAccess(session(), acct(account.StatusActive), client())
	if err != nil {
		t.Fatal(err)
	}

	header, claims := decode(t, got.Token)
	wantHeader := map[string]any{"alg": "RS256", "kid": rsaKid, "typ": "at+jwt"}
	if d := cmp.Diff(wantHeader, header); d != "" {
		t.Errorf("header (-want +got):\n%s", d)
	}
	wantClaims := map[string]any{
		"iss":       issuer,
		"sub":       accountID.String(),
		"aud":       appAudience,
		"iat":       num(now),
		"nbf":       num(now),
		"exp":       num(now.Add(15 * time.Minute)),
		"jti":       fakes.ID(1).String(),
		"sid":       sessionID.String(),
		"client_id": "web",
		"roles":     []any{"a", "b"},
		"status":    "active",
		"amr":       []any{"pwd", "otp", "mfa"},
		"auth_time": num(authTime),
	}
	if d := cmp.Diff(wantClaims, claims); d != "" {
		t.Errorf("claims (-want +got):\n%s", d)
	}

	wantAccess := tokens.Access{
		Token:      got.Token,
		ID:         fakes.ID(1),
		ExpiresAt:  time.Unix(now.Add(15*time.Minute).Unix(), 0).UTC(),
		Restricted: false,
	}
	if d := cmp.Diff(wantAccess, got); d != "" {
		t.Errorf("Access (-want +got):\n%s", d)
	}
}

func TestIssueAccessRestrictedClaims(t *testing.T) {
	t.Parallel()
	for _, status := range []account.Status{account.StatusSuspended, account.StatusBanned} {
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()
			e := newEnv(config())
			rsaKid, _ := e.keys.Kids()

			got, err := e.iss.IssueAccess(session(), acct(status), client())
			if err != nil {
				t.Fatal(err)
			}

			header, claims := decode(t, got.Token)
			wantHeader := map[string]any{"alg": "RS256", "kid": rsaKid, "typ": "at+jwt"}
			if d := cmp.Diff(wantHeader, header); d != "" {
				t.Errorf("header (-want +got):\n%s", d)
			}
			wantClaims := map[string]any{
				"iss":       issuer,
				"sub":       accountID.String(),
				"aud":       selfAudience,
				"iat":       num(now),
				"nbf":       num(now),
				"exp":       num(now.Add(15 * time.Minute)),
				"jti":       fakes.ID(1).String(),
				"sid":       sessionID.String(),
				"client_id": "web",
				"roles":     []any{},
				"status":    string(status),
				"amr":       []any{"pwd", "otp", "mfa"},
				"auth_time": num(authTime),
			}
			if d := cmp.Diff(wantClaims, claims); d != "" {
				t.Errorf("claims (-want +got):\n%s", d)
			}
			if !got.Restricted {
				t.Error("Restricted = false for a restricted session")
			}
		})
	}
}

func TestIssueAccessSelfAudienceDefaultsToIssuer(t *testing.T) {
	t.Parallel()
	cfg := config()
	cfg.SelfAudience = ""
	e := newEnv(cfg)

	got, err := e.iss.IssueAccess(session(), acct(account.StatusSuspended), client())
	if err != nil {
		t.Fatal(err)
	}
	if _, claims := decode(t, got.Token); claims["aud"] != issuer {
		t.Errorf("aud = %v, want the issuer %s", claims["aud"], issuer)
	}
}

func TestIssueAccessEmptySlices(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	s := session()
	s.AMR = nil
	c := client()
	c.AllowedRoles = nil

	got, err := e.iss.IssueAccess(s, acct(account.StatusActive), c)
	if err != nil {
		t.Fatal(err)
	}
	_, claims := decode(t, got.Token)
	for _, name := range []string{"roles", "amr"} {
		if d := cmp.Diff([]any{}, claims[name]); d != "" {
			t.Errorf("%s (-want +got):\n%s", name, d)
		}
	}
}

func TestIssueAccessRolesDeduplicated(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	a := acct(account.StatusActive)
	a.Roles = []string{"c", "a", "c", "z"}

	got, err := e.iss.IssueAccess(session(), a, client())
	if err != nil {
		t.Fatal(err)
	}
	if _, claims := decode(t, got.Token); !cmp.Equal([]any{"a", "c"}, claims["roles"]) {
		t.Errorf("roles = %v, want [a c]", claims["roles"])
	}
}

func TestIssueAccessRefuses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status account.Status
		mutate func(*env, *tokens.Session)
		want   error
	}{
		{name: "pending", status: account.StatusPending, want: tokens.ErrNotIssuable},
		{name: "deleted", status: account.StatusDeleted, want: tokens.ErrNotIssuable},
		{name: "unknown status", status: account.Status("frozen"), want: tokens.ErrNotIssuable},
		{
			name:   "session of another client",
			status: account.StatusActive,
			mutate: func(_ *env, s *tokens.Session) { s.ClientID = "mobile" },
			want:   tokens.ErrNotIssuable,
		},
		{
			name:   "no signing key",
			status: account.StatusActive,
			mutate: func(e *env, _ *tokens.Session) { e.keys.NoSigner() },
			want:   app.ErrNoSigningKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(config())
			s := session()
			if tt.mutate != nil {
				tt.mutate(e, &s)
			}
			got, err := e.iss.IssueAccess(s, acct(tt.status), client())
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if got.Token != "" {
				t.Error("a token alongside an error")
			}
		})
	}
}
