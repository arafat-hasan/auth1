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

// ServiceRoute returns a predicate telling, before dispatch, whether a request is for a service
// operation (security workload or serviceToken) mounted under basePath. L-1 exempts them: their
// callers share a sidecar's address (TDD-07 §8). It finds the route through the Chi router that
// is handling the request, so it works in middleware installed with Use.
func ServiceRoute(basePath string) func(*http.Request) bool {
	service := map[string]bool{}
	for _, op := range Operations {
		if slices.Contains(op.Security, "workload") || slices.Contains(op.Security, "serviceToken") {
			service[op.Method+" "+basePath+op.Path] = true
		}
	}
	return func(r *http.Request) bool {
		rctx := chi.RouteContext(r.Context())
		if rctx == nil || rctx.Routes == nil {
			return false
		}
		path := r.URL.RawPath
		if path == "" {
			path = r.URL.Path
		}
		return service[r.Method+" "+rctx.Routes.Find(chi.NewRouteContext(), r.Method, path)]
	}
}
