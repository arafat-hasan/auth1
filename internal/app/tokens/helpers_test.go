package tokens_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

const (
	issuer       = "https://auth.example.com"
	selfAudience = "https://auth.example.com/self"
	appAudience  = "https://api.example.com"
)

// now is the fake clock's start; its microseconds check that the claims are whole seconds.
var now = time.Date(2026, 11, 3, 10, 0, 0, 123456000, time.UTC)

// authTime is the sign-in time of the test session.
var authTime = time.Date(2026, 11, 3, 9, 55, 0, 0, time.UTC)

var (
	accountID = uuid.MustParse("019a4a3e-0000-7000-8000-00000000000a")
	sessionID = uuid.MustParse("019a4a3e-0000-7000-8000-00000000000b")
)

func config() tokens.Config {
	return tokens.Config{
		Issuer:          issuer,
		SelfAudience:    selfAudience,
		AccessTTL:       15 * time.Minute,
		ClientAudiences: []string{appAudience, "https://other.example.com"},
	}
}

func session() tokens.Session {
	return tokens.Session{ID: sessionID, ClientID: "web", AMR: []string{"pwd", "otp", "mfa"}, AuthTime: authTime}
}

func client() tokens.Client {
	return tokens.Client{ID: "web", Audience: appAudience, AllowedRoles: []string{"a", "b", "c"}}
}

func acct(status account.Status) tokens.Account {
	return tokens.Account{ID: accountID, Status: status, Roles: []string{"b", "x", "a"}}
}

// env is an issuer and a validator over one fake keyring and clock.
type env struct {
	keys  *fakes.Keys
	clock *fakes.Clock
	iss   *tokens.Issuer
	val   *tokens.Validator
}

func newEnv(cfg tokens.Config) *env {
	keys := fakes.NewKeys()
	clock := fakes.NewClock(now)
	return &env{
		keys:  keys,
		clock: clock,
		iss:   tokens.NewIssuer(cfg, keys, clock, fakes.NewIDs()),
		val:   tokens.NewValidator(cfg, keys, clock),
	}
}

// decode returns the protected header and the payload of the compact JWS tok, numbers as
// json.Number.
func decode(t *testing.T, tok string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	return segment(t, parts[0]), segment(t, parts[1])
}

func segment(t *testing.T, s string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url: %v", err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		t.Fatalf("json: %v", err)
	}
	return m
}

// num is the JSON number of a Unix time in seconds.
func num(t time.Time) json.Number {
	return json.Number(strconv.FormatInt(t.Unix(), 10))
}
