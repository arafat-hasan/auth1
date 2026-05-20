package utils

import (
	"fmt"
)

// Permission represents a permission in the system
type Permission string

const (
	// User permissions
	PermissionReadOwnProfile   Permission = "profile:read:own"
	PermissionWriteOwnProfile  Permission = "profile:write:own"
	PermissionDeleteOwnProfile Permission = "profile:delete:own"

	// Admin permissions
	PermissionReadAllProfiles   Permission = "profile:read:all"
	PermissionWriteAllProfiles  Permission = "profile:write:all"
	PermissionDeleteAllProfiles Permission = "profile:delete:all"
	PermissionManageUsers       Permission = "users:manage"
	PermissionManageRoles       Permission = "roles:manage"
	PermissionViewAuditLogs     Permission = "audit:read"

	// Moderator permissions
	PermissionModerateContent Permission = "content:moderate"
	PermissionReviewProfiles  Permission = "profiles:review"
	PermissionBanUsers        Permission = "users:ban"

	// Reviewer permissions
	PermissionReviewVerifications Permission = "verifications:review"
)

// RolePermissions maps roles to their permissions
var RolePermissions = map[string][]Permission{
	"user": {
		PermissionReadOwnProfile,
		PermissionWriteOwnProfile,
		PermissionDeleteOwnProfile,
	},
	"moderator": {
		PermissionReadOwnProfile,
		PermissionWriteOwnProfile,
		PermissionDeleteOwnProfile,
		PermissionModerateContent,
		PermissionReviewProfiles,
		PermissionBanUsers,
	},
	"reviewer": {
		PermissionReadOwnProfile,
		PermissionWriteOwnProfile,
		PermissionReviewVerifications,
	},
	"admin": {
		PermissionReadOwnProfile,
		PermissionWriteOwnProfile,
		PermissionDeleteOwnProfile,
		PermissionReadAllProfiles,
		PermissionWriteAllProfiles,
		PermissionDeleteAllProfiles,
		PermissionManageUsers,
		PermissionManageRoles,
		PermissionViewAuditLogs,
		PermissionModerateContent,
		PermissionReviewProfiles,
		PermissionBanUsers,
		PermissionReviewVerifications,
	},
}

// RBACManager manages role-based access control
type RBACManager struct {
	rolePermissions map[string][]Permission
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager() *RBACManager {
	return &RBACManager{
		rolePermissions: RolePermissions,
	}
}

// HasPermission checks if a role has a specific permission
func (m *RBACManager) HasPermission(role string, permission Permission) bool {
	permissions, exists := m.rolePermissions[role]
	if !exists {
		return false
	}

	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// GetPermissions returns all permissions for a role
func (m *RBACManager) GetPermissions(role string) []Permission {
	if permissions, exists := m.rolePermissions[role]; exists {
		return permissions
	}
	return []Permission{}
}

// ValidateRole checks if a role is valid
func (m *RBACManager) ValidateRole(role string) error {
	if _, exists := m.rolePermissions[role]; !exists {
		return fmt.Errorf("invalid role: %s", role)
	}
	return nil
}

// AddCustomPermission adds a custom permission to a role (for platform-specific use)
func (m *RBACManager) AddCustomPermission(role string, permission Permission) error {
	if _, exists := m.rolePermissions[role]; !exists {
		return fmt.Errorf("role does not exist: %s", role)
	}

	m.rolePermissions[role] = append(m.rolePermissions[role], permission)
	return nil
}

// CreateCustomRole creates a new custom role with specified permissions
func (m *RBACManager) CreateCustomRole(role string, permissions []Permission) error {
	if _, exists := m.rolePermissions[role]; exists {
		return fmt.Errorf("role already exists: %s", role)
	}

	m.rolePermissions[role] = permissions
	return nil
}

// RemoveRole removes a custom role (protected roles cannot be removed)
func (m *RBACManager) RemoveRole(role string) error {
	protectedRoles := []string{"user", "admin", "moderator", "reviewer"}
	for _, protected := range protectedRoles {
		if role == protected {
			return fmt.Errorf("cannot remove protected role: %s", role)
		}
	}

	delete(m.rolePermissions, role)
	return nil
}
