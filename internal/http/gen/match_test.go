package gen_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arafat-hasan/auth1/internal/http/gen"
)

// TestMatch: middleware installed with Use finds the operation a request will reach, by its route
// pattern under the base path, before the router dispatches it.
func TestMatch(t *testing.T) {
	t.Parallel()
	for _, basePath := range []string{"", "/auth"} {
		var (
			gotID string
			gotOp gen.Operation
			gotOK bool
		)
		record := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotID, gotOp, gotOK = gen.Match(basePath)(r)
				next.ServeHTTP(w, r)
			})
		}
		h := limitedRouter(t, basePath, record)
		for _, tc := range []struct {
			method, path string
			wantID       string // "" for no match
		}{
			{http.MethodPost, "/v1/introspect", "introspectToken"},
			{http.MethodPost, "/v1/accounts/0190a0a0-0000-7000-8000-000000000001/sessions/revoke", "revokeAccountSessions"},
			{http.MethodPut, "/v1/accounts/0190a0a0-0000-7000-8000-000000000001/roles", "setAccountRoles"},
			{http.MethodGet, "/.well-known/jwks.json", "getJwks"},
			{http.MethodGet, "/v1/introspect", ""},
			{http.MethodGet, "/v1/nope", ""},
		} {
			gotID, gotOp, gotOK = "", gen.Operation{}, false
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, basePath+tc.path, nil))
			if gotOK != (tc.wantID != "") || gotID != tc.wantID {
				t.Errorf("base %q: Match(%s %s) = %q, %v; want %q", basePath, tc.method, tc.path, gotID, gotOK, tc.wantID)
				continue
			}
			if gotOK && gotOp.Path != gen.Operations[tc.wantID].Path {
				t.Errorf("base %q: Match(%s %s) operation path %q, want %q", basePath, tc.method, tc.path, gotOp.Path, gen.Operations[tc.wantID].Path)
			}
		}
	}
}

// TestMatchOutsideBasePath: a request outside the base path matches no operation, though the same
// path would match without it.
func TestMatchOutsideBasePath(t *testing.T) {
	t.Parallel()
	var gotOK bool
	record := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _, gotOK = gen.Match("/auth")(r)
			next.ServeHTTP(w, r)
		})
	}
	// The router has no base path, so /v1/introspect reaches the API middleware, but a matcher for
	// /auth must not take it for introspectToken.
	h := limitedRouter(t, "", record)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/introspect", nil))
	if gotOK {
		t.Error(`Match("/auth") matched POST /v1/introspect`)
	}
}
