package account

import (
	"slices"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// TokenRoles returns the roles of a full token: the account's roles that the client allows,
// without duplicates, sorted, in a new slice (SDD D-6). An empty intersection is
// ROLE_NOT_PERMITTED. Restricted tokens carry no roles (TDD-04 §1); the catalogue is checked
// where roles are set, not here.
func TokenRoles(accountRoles, allowedRoles []string) ([]string, error) {
	var roles []string
	for _, r := range accountRoles {
		if slices.Contains(allowedRoles, r) && !slices.Contains(roles, r) {
			roles = append(roles, r)
		}
	}
	if len(roles) == 0 {
		return nil, &domain.Error{Code: domain.CodeRoleNotPermitted, Detail: "the account holds none of the client's roles"}
	}
	slices.Sort(roles)
	return roles, nil
}
