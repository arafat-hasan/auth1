package keyring

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/arafat-hasan/auth1/internal/app/tokens"
	"github.com/arafat-hasan/auth1/internal/domain/account"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
)

// TestTokensValidateAcrossRotation is R-1 on the validation side, with the real keyring: an access
// token signed before a rotation still validates while its key is published as retired, and is
// refused once the key leaves the file.
func TestTokensValidateAcrossRotation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := rsaKeys()[0]
	ec := ecKeys()[0]
	rsaKid, ecKid := kidOf(t, r), kidOf(t, ec)
	e.write(t, []spec{{alg: AlgRS256, state: StateActive, key: r}, {alg: AlgES256, state: StateNext, key: ec}})
	k := e.replica(t)
	e.promotable(t, rsaKid)
	e.promotable(t, ecKid)
	reload(t, k)

	cfg := tokens.Config{
		Issuer:          "https://auth.example.com",
		AccessTTL:       15 * time.Minute,
		ClientAudiences: []string{"https://api.example.com"},
	}
	clock := fakes.NewClock(time.Now())
	iss := tokens.NewIssuer(cfg, k, clock, fakes.NewIDs())
	val := tokens.NewValidator(cfg, k, clock)
	issue := func() string {
		t.Helper()
		a, err := iss.IssueAccess(
			tokens.Session{ID: uuid.New(), ClientID: "web", AMR: []string{"pwd"}, AuthTime: clock.Now()},
			tokens.Account{ID: uuid.New(), Status: account.StatusActive},
			tokens.Client{ID: "web", Audience: "https://api.example.com"},
		)
		if err != nil {
			t.Fatal(err)
		}
		return a.Token
	}

	before := issue()
	e.write(t, []spec{{alg: AlgRS256, state: StateRetired, key: r}, {alg: AlgES256, state: StateActive, key: ec}})
	reload(t, k)
	after := issue()

	for name, tok := range map[string]string{"before the rotation": before, "after the rotation": after} {
		if _, err := val.Validate(tok); err != nil {
			t.Errorf("token signed %s: %v", name, err)
		}
	}
	if kid := verify(t, k, after); kid != ecKid {
		t.Errorf("after the rotation signed by %s, want the ES256 key %s", kid, ecKid)
	}

	e.write(t, []spec{{alg: AlgES256, state: StateActive, key: ec}})
	reload(t, k)
	if _, err := val.Validate(before); !errors.Is(err, tokens.ErrUnknownKey) {
		t.Errorf("token of a key gone from the file: %v, want ErrUnknownKey", err)
	}
	if _, err := val.Validate(after); err != nil {
		t.Errorf("token of the active key: %v", err)
	}
}
