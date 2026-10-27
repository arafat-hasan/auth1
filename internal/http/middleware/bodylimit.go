package middleware

import (
	"net/http"

	"github.com/arafat-hasan/auth1/internal/http/problem"
)

// BodyLimit refuses request bodies over limit bytes (TDD-07 §7). A declared Content-Length over
// the limit is answered at once with 413 VALIDATION_FAILED through pw; any other body is wrapped
// in http.MaxBytesReader, so reading past the limit fails with *http.MaxBytesError, which pw
// renders the same way.
func BodyLimit(limit int64, pw *problem.Writer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				pw.Write(w, r, &http.MaxBytesError{Limit: limit})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}
