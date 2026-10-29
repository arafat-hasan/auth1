package gen

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/problem"
)

// invalidDetail is the detail of a request the generated code cannot bind. The binding error is
// not shown: it names Go types and repeats the caller's input.
const invalidDetail = "The request does not match the API contract."

// ErrNotImplemented is returned by an operation that has no handler yet; it answers 501.
var ErrNotImplemented = errors.New("not implemented")

var _ StrictServerInterface = Stub{}

// Routes returns the registration of every operation of api/openapi.yaml on a Chi router, for
// server.Options.Routes. Requests the generated code cannot bind answer 422 VALIDATION_FAILED;
// ErrNotImplemented answers 501; any other error from si is written by pw.
func Routes(si StrictServerInterface, pw *problem.Writer) func(chi.Router) {
	invalid := func(w http.ResponseWriter, r *http.Request, _ error) {
		pw.Write(w, r, &domain.Error{Code: domain.CodeValidationFailed, Detail: invalidDetail})
	}
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
