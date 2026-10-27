package middleware

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// otherMethod stands for any method outside knownMethods in span names, attributes, logs and
// metric labels, so an arbitrary method cannot create a new series (OpenTelemetry semantic
// conventions).
const otherMethod = "_OTHER"

// knownMethods are the methods of RFC 9110 and RFC 5789.
var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodDelete: true, http.MethodConnect: true, http.MethodOptions: true,
	http.MethodTrace: true, http.MethodPatch: true,
}

// normalMethod returns m when it is a known method, else otherMethod.
func normalMethod(m string) string {
	if knownMethods[m] {
		return m
	}
	return otherMethod
}

// routePattern returns the Chi route pattern that matched r, or "" when none did. It is complete
// only after the router has handled r.
func routePattern(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		return rctx.RoutePattern()
	}
	return ""
}

// wrap returns w as a WrapResponseWriter, reusing it when an outer middleware already wrapped it.
func wrap(w http.ResponseWriter, r *http.Request) chimw.WrapResponseWriter {
	if ww, ok := w.(chimw.WrapResponseWriter); ok {
		return ww
	}
	return chimw.NewWrapResponseWriter(w, r.ProtoMajor)
}

// abortedType is the error.type of a request whose handler aborted with http.ErrAbortHandler.
const abortedType = "aborted"

// responseStatus returns the status ww sent. When the handler wrote nothing it is 200, which
// net/http then answers, unless the handler aborted: then it is 0, as nothing was sent.
func responseStatus(ww chimw.WrapResponseWriter, aborted bool) int {
	if s := ww.Status(); s != 0 || aborted {
		return s
	}
	return http.StatusOK
}
