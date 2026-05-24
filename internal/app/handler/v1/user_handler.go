package v1

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/arafat-hasan/auth1/internal/app/middleware"
	"github.com/arafat-hasan/auth1/internal/app/model/api"
	"github.com/arafat-hasan/auth1/internal/app/model/domain"
	"github.com/arafat-hasan/auth1/internal/service"
)

// UserHandler handles admin user management HTTP requests.
type UserHandler struct {
	authService service.AuthService
	validator   *validator.Validate
	logger      *logrus.Logger
}

func NewUserHandler(authService service.AuthService, logger *logrus.Logger) *UserHandler {
	return &UserHandler{
		authService: authService,
		validator:   validator.New(),
		logger:      logger,
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (h *UserHandler) requesterID(r *http.Request) uuid.UUID {
	id, _ := r.Context().Value("user_id").(uuid.UUID)
	return id
}

func (h *UserHandler) requesterRoles(r *http.Request) []string {
	roles, _ := r.Context().Value("roles").([]string)
	return roles
}

func (h *UserHandler) renderErr(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	render.Status(r, status)
	render.JSON(w, r, &api.ErrorResponse{Error: code, Message: msg, Success: false})
}

func (h *UserHandler) renderOK(w http.ResponseWriter, r *http.Request, msg string) {
	render.Status(r, http.StatusOK)
	render.JSON(w, r, &api.SuccessResponse{Message: msg, Success: true})
}

func (h *UserHandler) parseTargetID(r *http.Request) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, "id"))
}

func isAdminRole(roles []string) bool {
	for _, r := range roles {
		if r == "admin" {
			return true
		}
	}
	return false
}

func userToAdminResponse(u *domain.User) api.UserAdminResponse {
	return api.UserAdminResponse{
		ID:                  u.ID,
		Email:               u.Email,
		Name:                u.Name,
		Phone:               u.Phone,
		Role:                u.Role,
		IsVerified:          u.IsVerified,
		IsActive:            u.IsActive,
		Is2FAEnabled:        u.Is2FAEnabled,
		FailedLoginAttempts: u.FailedLoginAttempts,
		LockedUntil:         u.LockedUntil,
		LastLoginAt:         u.LastLoginAt,
		CreatedAt:           u.CreatedAt,
		UpdatedAt:           u.UpdatedAt,
		Metadata:            u.Metadata,
	}
}

// ── GET /api/v1/users ─────────────────────────────────────────────────────────

// ListUsers lists users with optional pagination and filtering (admin only).
// @Summary List users (admin)
// @Description List all users with optional search, role, and active-status filters. Supports pagination.
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size max 100" default(20)
// @Param search query string false "Search email or name"
// @Param role query string false "Filter by role"
// @Param is_active query bool false "Filter by active status"
// @Success 200 {object} api.ListUsersResponse
// @Failure 403 {object} api.ErrorResponse
// @Router /api/v1/users [get]
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}

	req := &service.ListUsersRequest{
		Page:     page,
		PageSize: pageSize,
		Search:   q.Get("search"),
		Role:     q.Get("role"),
	}
	if v := q.Get("is_active"); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			req.IsActive = &b
		}
	}

	result, err := h.authService.ListUsers(r.Context(), req)
	if err != nil {
		h.logger.WithError(err).Error("ListUsers failed")
		h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to list users")
		return
	}

	users := make([]api.UserAdminResponse, len(result.Users))
	for i, u := range result.Users {
		users[i] = userToAdminResponse(u)
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, &api.ListUsersResponse{
		Users:      users,
		Total:      result.Total,
		Page:       result.Page,
		PageSize:   result.PageSize,
		TotalPages: result.TotalPages,
	})
}

// ── GET /api/v1/users/:id ─────────────────────────────────────────────────────

// GetUser returns a single user by ID with full admin detail.
// @Summary Get user by ID (admin)
// @Description Get full admin detail for a single user by UUID
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param id path string true "User UUID"
// @Success 200 {object} api.UserAdminResponse
// @Failure 404 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /api/v1/users/{id} [get]
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	targetID, err := h.parseTargetID(r)
	if err != nil {
		h.renderErr(w, r, http.StatusBadRequest, "invalid_id", "Invalid user ID")
		return
	}

	user, err := h.authService.GetUserByID(r.Context(), targetID)
	if err != nil {
		h.logger.WithError(err).Error("GetUser failed")
		h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to get user")
		return
	}
	if user == nil {
		h.renderErr(w, r, http.StatusNotFound, "user_not_found", "User not found")
		return
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, userToAdminResponse(user))
}

// ── PUT /api/v1/users/:id ─────────────────────────────────────────────────────

// UpdateUser updates profile, role, and/or metadata for a user (admin only).
// @Summary Update user (admin)
// @Description Update profile fields, role, and/or metadata in a single request (all fields optional)
// @Tags admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path string true "User UUID"
// @Param request body api.UpdateUserAdminRequest true "Update request"
// @Success 200 {object} api.SuccessResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 403 {object} api.ErrorResponse
// @Failure 404 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /api/v1/users/{id} [put]
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	targetID, err := h.parseTargetID(r)
	if err != nil {
		h.renderErr(w, r, http.StatusBadRequest, "invalid_id", "Invalid user ID")
		return
	}

	var req api.UpdateUserAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.renderErr(w, r, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if err := h.validator.Struct(req); err != nil {
		h.renderErr(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	adminID := h.requesterID(r)
	ip := middleware.GetClientIP(r)

	if req.Name != nil || req.Email != nil || req.Phone != nil {
		if err := h.authService.UpdateUser(r.Context(), targetID, &service.UpdateUserRequest{
			Name:  req.Name,
			Email: req.Email,
			Phone: req.Phone,
		}); err != nil {
			h.logger.WithError(err).Error("UpdateUser profile failed")
			if err.Error() == "user not found" {
				h.renderErr(w, r, http.StatusNotFound, "user_not_found", "User not found")
				return
			}
			h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to update user")
			return
		}
		h.authService.AuditAdminAction(r.Context(), adminID, "user.updated", map[string]interface{}{
			"target_user_id": targetID, "admin_id": adminID,
		}, ip)
	}

	if req.Role != nil {
		if err := h.authService.UpdateUserRole(r.Context(), targetID, *req.Role); err != nil {
			h.logger.WithError(err).Error("UpdateUserRole failed")
			h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to update role")
			return
		}
		h.authService.AuditAdminAction(r.Context(), adminID, "user.role_changed", map[string]interface{}{
			"target_user_id": targetID, "admin_id": adminID, "new_role": *req.Role,
		}, ip)
	}

	if req.Metadata != nil {
		if err := h.authService.UpdateUserMetadata(r.Context(), targetID, req.Metadata); err != nil {
			h.logger.WithError(err).Error("UpdateUserMetadata failed")
			h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to update metadata")
			return
		}
		h.authService.AuditAdminAction(r.Context(), adminID, "user.metadata_updated", map[string]interface{}{
			"target_user_id": targetID, "admin_id": adminID,
		}, ip)
	}

	h.renderOK(w, r, "User updated successfully")
}

// ── POST /api/v1/users/:id/deactivate ────────────────────────────────────────

// DeactivateUser deactivates a user account and revokes all sessions (admin only).
// @Summary Deactivate user (admin)
// @Description Deactivate user account and immediately revoke all active sessions
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param id path string true "User UUID"
// @Success 200 {object} api.SuccessResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /api/v1/users/{id}/deactivate [post]
func (h *UserHandler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	targetID, err := h.parseTargetID(r)
	if err != nil {
		h.renderErr(w, r, http.StatusBadRequest, "invalid_id", "Invalid user ID")
		return
	}

	adminID := h.requesterID(r)
	if targetID == adminID {
		h.renderErr(w, r, http.StatusBadRequest, "self_action", "Cannot deactivate your own account")
		return
	}

	if err := h.authService.DeactivateUser(r.Context(), targetID); err != nil {
		h.logger.WithError(err).Error("DeactivateUser failed")
		h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to deactivate user")
		return
	}

	h.authService.AuditAdminAction(r.Context(), adminID, "user.deactivated", map[string]interface{}{
		"target_user_id": targetID, "admin_id": adminID,
	}, middleware.GetClientIP(r))

	h.renderOK(w, r, "User deactivated successfully")
}

// ── POST /api/v1/users/:id/reactivate ────────────────────────────────────────

// ReactivateUser reactivates a previously deactivated user account (admin only).
// @Summary Reactivate user (admin)
// @Description Restore a deactivated user account
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param id path string true "User UUID"
// @Success 200 {object} api.SuccessResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /api/v1/users/{id}/reactivate [post]
func (h *UserHandler) ReactivateUser(w http.ResponseWriter, r *http.Request) {
	targetID, err := h.parseTargetID(r)
	if err != nil {
		h.renderErr(w, r, http.StatusBadRequest, "invalid_id", "Invalid user ID")
		return
	}

	if err := h.authService.ReactivateUser(r.Context(), targetID); err != nil {
		h.logger.WithError(err).Error("ReactivateUser failed")
		h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to reactivate user")
		return
	}

	adminID := h.requesterID(r)
	h.authService.AuditAdminAction(r.Context(), adminID, "user.reactivated", map[string]interface{}{
		"target_user_id": targetID, "admin_id": adminID,
	}, middleware.GetClientIP(r))

	h.renderOK(w, r, "User reactivated successfully")
}

// ── DELETE /api/v1/users/:id ─────────────────────────────────────────────────

// DeleteUser soft-deletes a user and revokes all sessions (admin only).
// @Summary Delete user (admin)
// @Description Soft-delete a user and immediately revoke all active sessions
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param id path string true "User UUID"
// @Success 200 {object} api.SuccessResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /api/v1/users/{id} [delete]
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	targetID, err := h.parseTargetID(r)
	if err != nil {
		h.renderErr(w, r, http.StatusBadRequest, "invalid_id", "Invalid user ID")
		return
	}

	adminID := h.requesterID(r)
	if targetID == adminID {
		h.renderErr(w, r, http.StatusBadRequest, "self_action", "Cannot delete your own account")
		return
	}

	if err := h.authService.DeleteUser(r.Context(), targetID); err != nil {
		h.logger.WithError(err).Error("DeleteUser failed")
		h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to delete user")
		return
	}

	h.authService.AuditAdminAction(r.Context(), adminID, "user.deleted", map[string]interface{}{
		"target_user_id": targetID, "admin_id": adminID,
	}, middleware.GetClientIP(r))

	h.renderOK(w, r, "User deleted successfully")
}

// ── POST /api/v1/users/:id/unlock ────────────────────────────────────────────

// UnlockUser manually unlocks a locked user account (admin only).
// @Summary Unlock user account (admin)
// @Description Manually clear failed login attempts and remove account lockout
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param id path string true "User UUID"
// @Success 200 {object} api.SuccessResponse
// @Failure 400 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /api/v1/users/{id}/unlock [post]
func (h *UserHandler) UnlockUser(w http.ResponseWriter, r *http.Request) {
	targetID, err := h.parseTargetID(r)
	if err != nil {
		h.renderErr(w, r, http.StatusBadRequest, "invalid_id", "Invalid user ID")
		return
	}

	if err := h.authService.UnlockAccount(r.Context(), targetID); err != nil {
		h.logger.WithError(err).Error("UnlockAccount failed")
		h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to unlock account")
		return
	}

	adminID := h.requesterID(r)
	h.authService.AuditAdminAction(r.Context(), adminID, "user.unlocked", map[string]interface{}{
		"target_user_id": targetID, "admin_id": adminID,
	}, middleware.GetClientIP(r))

	h.renderOK(w, r, "Account unlocked successfully")
}

// ── GET /api/v1/users/:id/sessions ───────────────────────────────────────────

// ListUserSessions lists active sessions for a user.
// Admin can view any user; regular user can only view their own.
// @Summary List user sessions
// @Description Returns JTIs of all active refresh tokens. Admin can view any user; regular user can only view their own.
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param id path string true "User UUID"
// @Success 200 {object} api.ListSessionsResponse
// @Failure 403 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /api/v1/users/{id}/sessions [get]
func (h *UserHandler) ListUserSessions(w http.ResponseWriter, r *http.Request) {
	targetID, err := h.parseTargetID(r)
	if err != nil {
		h.renderErr(w, r, http.StatusBadRequest, "invalid_id", "Invalid user ID")
		return
	}

	requesterID := h.requesterID(r)
	if !isAdminRole(h.requesterRoles(r)) && requesterID != targetID {
		h.renderErr(w, r, http.StatusForbidden, "forbidden", "Cannot view another user's sessions")
		return
	}

	jtis, err := h.authService.ListUserSessions(r.Context(), targetID)
	if err != nil {
		h.logger.WithError(err).Error("ListUserSessions failed")
		h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to list sessions")
		return
	}

	items := make([]api.SessionItem, len(jtis))
	for i, jti := range jtis {
		items[i] = api.SessionItem{SessionID: jti}
	}

	render.Status(r, http.StatusOK)
	render.JSON(w, r, &api.ListSessionsResponse{Sessions: items, Total: len(items)})
}

// ── DELETE /api/v1/users/:id/sessions/:session_id ────────────────────────────

// RevokeUserSession revokes a specific session by JTI.
// Admin can revoke any session; regular user can only revoke their own.
// @Summary Revoke a user session
// @Description Revoke a specific session by its JTI. Admin can revoke any session; regular user can only revoke their own.
// @Tags users
// @Security BearerAuth
// @Produce json
// @Param id path string true "User UUID"
// @Param session_id path string true "Session ID (JTI)"
// @Success 200 {object} api.SuccessResponse
// @Failure 403 {object} api.ErrorResponse
// @Failure 404 {object} api.ErrorResponse
// @Failure 500 {object} api.ErrorResponse
// @Router /api/v1/users/{id}/sessions/{session_id} [delete]
func (h *UserHandler) RevokeUserSession(w http.ResponseWriter, r *http.Request) {
	targetID, err := h.parseTargetID(r)
	if err != nil {
		h.renderErr(w, r, http.StatusBadRequest, "invalid_id", "Invalid user ID")
		return
	}

	sessionID := chi.URLParam(r, "session_id")
	if sessionID == "" {
		h.renderErr(w, r, http.StatusBadRequest, "invalid_session_id", "Missing session ID")
		return
	}

	requesterID := h.requesterID(r)
	if !isAdminRole(h.requesterRoles(r)) && requesterID != targetID {
		h.renderErr(w, r, http.StatusForbidden, "forbidden", "Cannot revoke another user's session")
		return
	}

	if err := h.authService.RevokeUserSession(r.Context(), targetID, sessionID); err != nil {
		h.logger.WithError(err).Error("RevokeUserSession failed")
		if err.Error() == "session not found" {
			h.renderErr(w, r, http.StatusNotFound, "session_not_found", "Session not found")
			return
		}
		h.renderErr(w, r, http.StatusInternalServerError, "internal_error", "Failed to revoke session")
		return
	}

	h.authService.AuditAdminAction(r.Context(), requesterID, "user.session_revoked", map[string]interface{}{
		"target_user_id": targetID,
		"session_id":     sessionID,
		"actor_id":       requesterID,
	}, middleware.GetClientIP(r))

	h.renderOK(w, r, "Session revoked successfully")
}
