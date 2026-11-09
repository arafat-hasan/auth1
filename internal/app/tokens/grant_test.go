package tokens_test

import (
	"testing"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

func TestIssueGrant(t *testing.T) {
	t.Parallel()
	e := newEnv(config())
	s, a, c := session(), acct(account.StatusActive), client()
	g := app.AccessGrant{SessionID: s.ID, ClientID: s.ClientID, AMR: s.AMR, AuthTime: s.AuthTime,
		AccountID: a.ID, Status: a.Status, Roles: a.Roles, Audience: c.Audience, Allowed: c.AllowedRoles}
	var issuer app.AccessIssuer = e.iss
	got, err := issuer.Issue(g)
	if err != nil {
		t.Fatal(err)
	}
	_, claims := decode(t, got.Token)
	if claims["aud"] != appAudience || claims["sid"] != s.ID.String() || got.Restricted {
		t.Errorf("claims %v, restricted %v; want the full token of the grant", claims, got.Restricted)
	}
	g.Status = account.StatusBanned
	if got, err = issuer.Issue(g); err != nil || !got.Restricted {
		t.Errorf("banned: %v, %v; want a restricted token", got, err)
	}
	g.Status = account.StatusDeleted
	if _, err := issuer.Issue(g); err == nil {
		t.Error("deleted: issued")
	}
}
