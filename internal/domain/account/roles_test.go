package account

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// TestT13TokenRoles checks that token roles are the account's roles that the client allows,
// and that an empty intersection is ROLE_NOT_PERMITTED (SDD D-6).
func TestT13TokenRoles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		account, allowed []string
		want             []string // nil: ROLE_NOT_PERMITTED
	}{
		{"one in common", []string{"user", "admin"}, []string{"admin"}, []string{"admin"}},
		{"all in common", []string{"user", "admin"}, []string{"admin", "user"}, []string{"admin", "user"}},
		{"sorted and unique", []string{"user", "admin", "user", "ops"}, []string{"user", "admin", "admin", "ops"},
			[]string{"admin", "ops", "user"}},
		{"none in common", []string{"user"}, []string{"admin"}, nil},
		{"no account roles", nil, []string{"admin"}, nil},
		{"no allowed roles", []string{"admin"}, nil, nil},
		{"both empty", []string{}, []string{}, nil},
		{"case-sensitive", []string{"Admin"}, []string{"admin"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := TokenRoles(tt.account, tt.allowed)
			if tt.want == nil {
				if got != nil {
					t.Errorf("roles = %v, want none", got)
				}
				checkError(t, err, domain.CodeRoleNotPermitted, nil)
				return
			}
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("roles (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTokenRolesDoesNotMutate(t *testing.T) {
	t.Parallel()

	account := []string{"user", "admin", "ops"}
	allowed := []string{"user", "ops"}
	accountBefore, allowedBefore := slices.Clone(account), slices.Clone(allowed)

	got, err := TokenRoles(account, allowed)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	got[0] = "changed"
	if diff := cmp.Diff(accountBefore, account); diff != "" {
		t.Errorf("account roles changed (-before +after):\n%s", diff)
	}
	if diff := cmp.Diff(allowedBefore, allowed); diff != "" {
		t.Errorf("allowed roles changed (-before +after):\n%s", diff)
	}
}
