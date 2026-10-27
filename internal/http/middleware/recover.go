package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/problem"
	"github.com/arafat-hasan/auth1/internal/http/requestid"
	"github.com/arafat-hasan/auth1/internal/telemetry"
)

// panicDetail is the detail of the problem a recovered panic answers.
const panicDetail = "The service is temporarily unavailable."

// Recover turns a handler panic into a 503 UNAVAILABLE problem, written with pw, and logs it at
// error with its stack, so the server keeps serving. The panic value is logged only when it is an
// error; otherwise only its type is, since a value could hold request data (G-6). When the
// response has already started, nothing more is written. http.ErrAbortHandler is re-panicked, so
// net/http still aborts the response.
func Recover(logger *slog.Logger, pw *problem.Writer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := wrap(w, r)
			defer func() {
				v := recover()
				if v == nil {
					return
				}
				if v == http.ErrAbortHandler { //nolint:errorlint // net/http panics with the sentinel itself
					panic(v)
				}
				logger.LogAttrs(r.Context(), slog.LevelError, "handler panicked",
					slog.String("panic", panicValue(v)),
					slog.String("stack", string(debug.Stack())),
					telemetry.RequestID(requestid.From(r.Context())))
				if ww.Status() == 0 {
					pw.Write(ww, r, &domain.Error{Code: domain.CodeUnavailable, Detail: panicDetail})
				}
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

// panicValue is the message of an error panic value, else the value's type.
func panicValue(v any) string {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	return fmt.Sprintf("%T", v)
}
