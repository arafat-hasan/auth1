package api

import (
	"time"

	"github.com/google/uuid"
)

// UserAdminResponse is the full user view returned to admins.
// @Description Full user detail for admin endpoints
type UserAdminResponse struct {
	ID                  uuid.UUID              `json:"id"`
	Email               string                 `json:"email"`
	Name                string                 `json:"name"`
	Phone               *string                `json:"phone,omitempty"`
	Role                string                 `json:"role"`
	IsVerified          bool                   `json:"is_verified"`
	IsActive            bool                   `json:"is_active"`
	Is2FAEnabled        bool                   `json:"is_2fa_enabled"`
	FailedLoginAttempts int                    `json:"failed_login_attempts"`
	LockedUntil         *time.Time             `json:"locked_until,omitempty"`
	LastLoginAt         *time.Time             `json:"last_login_at,omitempty"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
}

// ListUsersResponse is the paginated user list returned to admins.
// @Description Paginated list of users
type ListUsersResponse struct {
	Users      []UserAdminResponse `json:"users"`
	Total      int                 `json:"total"`
	Page       int                 `json:"page"`
	PageSize   int                 `json:"page_size"`
	TotalPages int                 `json:"total_pages"`
}

// UpdateUserAdminRequest supports partial update of profile, role, and metadata.
// @Description Admin update user request
type UpdateUserAdminRequest struct {
	Name     *string                `json:"name,omitempty"`
	Email    *string                `json:"email,omitempty" validate:"omitempty,email"`
	Phone    *string                `json:"phone,omitempty"`
	Role     *string                `json:"role,omitempty" validate:"omitempty,oneof=user admin moderator reviewer"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// SessionItem represents one active session (identified by the refresh token JTI).
// @Description Active session info
type SessionItem struct {
	SessionID string `json:"session_id"`
}

// ListSessionsResponse holds active sessions for a user.
// @Description List of active sessions
type ListSessionsResponse struct {
	Sessions []SessionItem `json:"sessions"`
	Total    int           `json:"total"`
}
