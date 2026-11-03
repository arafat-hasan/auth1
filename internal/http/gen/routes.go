package gen

import (
	"errors"
	"net/http"
	"slices"

	"github.com/go-chi/chi/v5"

	"github.com/arafat-hasan/auth1/internal/http/problem"
)

// ErrNotImplemented is returned by an operation that has no handler yet; it answers 501.
var ErrNotImplemented = errors.New("not implemented")

var _ StrictServerInterface = Stub{}

// Routes returns the registration of every operation of api/openapi.yaml on a Chi router, for
// server.Options.Routes. Requests the generated code cannot bind answer 422 VALIDATION_FAILED,
// or 413 when the body is over the limit (pw.WriteBindError); ErrNotImplemented answers 501; any
// other error from si is written by pw.
func Routes(si StrictServerInterface, pw *problem.Writer) func(chi.Router) {
	invalid := pw.WriteBindError
	failed := func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, ErrNotImplemented) {
			pw.WriteNotImplemented(w, r)
			return
		}
		pw.Write(w, r, err)
	}
	h := NewStrictHandlerWithOptions(si, nil, StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  invalid,
		ResponseErrorHandlerFunc: failed,
	})
	return func(r chi.Router) {
		HandlerWithOptions(h, ChiServerOptions{BaseRouter: r, ErrorHandlerFunc: invalid})
	}
}

// The security schemes of service operations, as api/openapi.yaml names them.
const (
	SchemeWorkload     = "workload"
	SchemeServiceToken = "serviceToken"
)

// IsService reports whether op is a service operation: one whose security is workload or
// serviceToken.
func (op Operation) IsService() bool {
	return slices.Contains(op.Security, SchemeWorkload) || slices.Contains(op.Security, SchemeServiceToken)
}

// Match returns a function finding, before dispatch, the operation a request is for among those
// mounted under basePath: its id and route metadata, or ok false for none. It asks the Chi router
// handling the request which route pattern the path matches, and keys on that pattern, never on
// the request path itself, so it works in middleware installed with Use.
func Match(basePath string) func(*http.Request) (id string, op Operation, ok bool) {
	byRoute := make(map[string]string, len(Operations))
	for id, op := range Operations {
		byRoute[op.Method+" "+basePath+op.Path] = id
	}
	return func(r *http.Request) (string, Operation, bool) {
		rctx := chi.RouteContext(r.Context())
		if rctx == nil || rctx.Routes == nil {
			return "", Operation{}, false
		}
		path := r.URL.RawPath
		if path == "" {
			path = r.URL.Path
		}
		id, ok := byRoute[r.Method+" "+rctx.Routes.Find(chi.NewRouteContext(), r.Method, path)]
		if !ok {
			return "", Operation{}, false
		}
		return id, Operations[id], true
	}
}

// ServiceRoute returns a predicate telling, before dispatch, whether a request is for a service
// operation mounted under basePath (Match). L-1 exempts them: their callers share a sidecar's
// address (TDD-07 §8).
func ServiceRoute(basePath string) func(*http.Request) bool {
	match := Match(basePath)
	return func(r *http.Request) bool {
		_, op, ok := match(r)
		return ok && op.IsService()
	}
}
