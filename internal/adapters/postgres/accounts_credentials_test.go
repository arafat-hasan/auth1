package postgres_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/domain/account"
)

// roles returns the account's roles, failing the test on an error.
func (e *accountsEnv) roles(t *testing.T, na account.NewAccount) []account.Role {
	t.Helper()
	roles, err := e.repo.Roles(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	return roles
}

func TestSetRolesReplacesSet(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	na.Roles = []string{"member", "editor"}
	e.create(t, na)
	before := e.roles(t, na)
	want := []account.Role{{Name: "editor", GrantedBy: "system"}, {Name: "member", GrantedBy: "system"}}
	if diff := cmp.Diff(want, before, cmpopts.IgnoreFields(account.Role{}, "GrantedAt")); diff != "" {
		t.Fatalf("roles after create (-want +got):\n%s", diff)
	}

	e.exec(t, "UPDATE account_roles SET granted_at = now() - interval '1 day' WHERE account_id = ?", na.ID)
	kept := e.roles(t, na)[1].GrantedAt
	if err := e.repo.SetRoles(t.Context(), na.ID, []string{"member", "admin"}, "operator:7"); err != nil {
		t.Fatal(err)
	}
	got := e.roles(t, na)
	want = []account.Role{{Name: "admin", GrantedBy: "operator:7"}, {Name: "member", GrantedBy: "system", GrantedAt: kept}}
	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(account.Role{}, "GrantedAt")); diff != "" {
		t.Errorf("roles after set (-want +got):\n%s", diff)
	}
	if !got[1].GrantedAt.Equal(kept) || !got[0].GrantedAt.After(kept) {
		t.Errorf("granted at = %v, %v; want the kept role's grant unchanged", got[0].GrantedAt, got[1].GrantedAt)
	}

	if err := e.repo.SetRoles(t.Context(), na.ID, nil, ""); err != nil {
		t.Fatal(err)
	}
	if got := e.roles(t, na); len(got) != 0 {
		t.Errorf("roles after clearing: %v", got)
	}
}

// TestSetPasswordReplaces checks the password round-trip, with the pepper key id kept as text.
func TestSetPasswordReplaces(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	got, err := e.repo.PasswordCredential(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != na.Password.Hash || got.PepperKID != "3" || got.ChangedAt.IsZero() {
		t.Errorf("password after create = %+v", got)
	}

	if err := e.repo.SetPassword(t.Context(), na.ID, "$argon2id$v=19$m=65536,t=3,p=1$bmV3$bmV3", "12"); err != nil {
		t.Fatal(err)
	}
	got, err = e.repo.PasswordCredential(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != "$argon2id$v=19$m=65536,t=3,p=1$bmV3$bmV3" || got.PepperKID != "12" {
		t.Errorf("password after replace = %+v", got)
	}
	_, err = e.repo.PasswordCredential(t.Context(), e.ids.New())
	checkCode(t, err, domain.CodeNotFound)
}

func TestActivate(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	e.exec(t, "UPDATE accounts SET status_changed_at = now() - interval '1 hour' WHERE id = ?", na.ID)
	before, err := e.repo.Get(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.do(t, func(ctx context.Context) error { return e.repo.Activate(ctx, na.ID) })
	got, err := e.repo.Get(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != account.StatusActive || !got.StatusChangedAt.After(before.StatusChangedAt) {
		t.Errorf("after activation: status %s, changed at %v", got.Status, got.StatusChangedAt)
	}
	// Only a pending account is activated.
	if err := e.repo.Activate(t.Context(), na.ID); err == nil {
		t.Error("activating an active account succeeded")
	}
}

// TestActivateWithoutPasswordRefused checks that activation keeps I-17: a pending account without
// a password stays pending.
func TestActivateWithoutPasswordRefused(t *testing.T) {
	t.Parallel()
	e := accountsDB(t)
	na := e.newAccount("", "ada@example.org")
	e.create(t, na)
	e.exec(t, "DELETE FROM password_credentials WHERE account_id = ?", na.ID)
	if err := e.repo.Activate(t.Context(), na.ID); err == nil {
		t.Error("activation without a password succeeded")
	}
	got, err := e.repo.Get(t.Context(), na.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != account.StatusPending {
		t.Errorf("status = %s, want pending", got.Status)
	}
}
