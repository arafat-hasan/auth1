package problem

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/requestid"
	"github.com/arafat-hasan/auth1/internal/telemetry"
)

// ContentType is the media type of a problem response.
const ContentType = "application/problem+json"

// unavailableDetail is the detail of an error that is not a domain.Error.
const unavailableDetail = "The service is temporarily unavailable."

// statuses is SDD §10: the HTTP status of each code.
var statuses = map[domain.Code]int{
	domain.CodeValidationFailed:         http.StatusUnprocessableEntity,
	domain.CodeIdentifierNotAllowed:     http.StatusUnprocessableEntity,
	domain.CodePasswordRejected:         http.StatusUnprocessableEntity,
	domain.CodeIdentifierTaken:          http.StatusConflict,
	domain.CodeVerificationIncomplete:   http.StatusConflict,
	domain.CodeCodeInvalid:              http.StatusBadRequest,
	domain.CodeChallengeClosed:          http.StatusGone,
	domain.CodeResendTooSoon:            http.StatusTooManyRequests,
	domain.CodeInvalidCredentials:       http.StatusUnauthorized,
	domain.CodeSignInDelayed:            http.StatusTooManyRequests,
	domain.CodeRegistrationIncomplete:   http.StatusForbidden,
	domain.CodeRoleNotPermitted:         http.StatusForbidden,
	domain.CodeAccountRestricted:        http.StatusForbidden,
	domain.CodeSessionInvalid:           http.StatusUnauthorized,
	domain.CodeTokenInvalid:             http.StatusUnauthorized,
	domain.CodeReauthenticationRequired: http.StatusForbidden,
	domain.CodeCallerNotAllowed:         http.StatusForbidden,
	domain.CodeIdempotencyKeyReused:     http.StatusUnprocessableEntity,
	domain.CodeStatusTransitionInvalid:  http.StatusConflict,
	domain.CodeMFAStateInvalid:          http.StatusConflict,
	domain.CodeRoleUnknown:              http.StatusUnprocessableEntity,
	domain.CodeNotFound:                 http.StatusNotFound,
	domain.CodeRateLimited:              http.StatusTooManyRequests,
	domain.CodeUnavailable:              http.StatusServiceUnavailable,
}

// Status returns the HTTP status of code, and false for a code outside the catalogue.
func Status(code domain.Code) (int, bool) {
	s, ok := statuses[code]
	return s, ok
}

// body is the Problem schema of api/openapi.yaml.
type body struct {
	Type         string       `json:"type"`
	Title        string       `json:"title"`
	Status       int          `json:"status"`
	Code         domain.Code  `json:"code"`
	Detail       string       `json:"detail,omitempty"`
	RetryAfter   int64        `json:"retry_after,omitempty"`
	AttemptsLeft *int         `json:"attempts_left,omitempty"`
	Reasons      []string     `json:"reasons,omitempty"`
	Errors       []fieldError `json:"errors,omitempty"`
}

type fieldError struct {
	Field string `json:"field"`
	Code  string `json:"code"`
}

// Writer writes problem responses. Errors that are not domain errors are logged with logger.
type Writer struct {
	logger *slog.Logger
}

// New returns a Writer logging unexpected errors to logger.
func New(logger *slog.Logger) *Writer {
	return &Writer{logger: logger}
}

// Write renders err as application/problem+json. A *domain.Error renders with its code's status
// and its optional members; retry_after also sets Retry-After. An *http.MaxBytesError renders as
// 413 VALIDATION_FAILED (SDD §10). Any other error renders as 503 UNAVAILABLE with a generic
// detail and no retry hint, and is logged with its cause.
func (pw *Writer) Write(w http.ResponseWriter, r *http.Request, err error) {
	var (
		de *domain.Error
		me *http.MaxBytesError
		b  body
	)
	switch {
	case errors.As(err, &de):
		status, ok := Status(de.Code)
		if !ok {
			b = pw.unexpected(r, fmt.Errorf("unknown error code %q: %w", de.Code, err))
			break
		}
		b = body{Status: status, Code: de.Code, Detail: de.Detail, AttemptsLeft: de.AttemptsLeft, Reasons: de.Reasons}
		if de.RetryAfter > 0 {
			b.RetryAfter = max(1, int64(math.Ceil(de.RetryAfter.Seconds())))
		}
		for _, f := range de.Fields {
			b.Errors = append(b.Errors, fieldError(f))
		}
	case errors.As(err, &me):
		b = body{
			Status: http.StatusRequestEntityTooLarge,
			Code:   domain.CodeValidationFailed,
			Detail: fmt.Sprintf("The request body exceeds %d bytes.", me.Limit),
		}
	default:
		b = pw.unexpected(r, err)
	}
	b.Type = "about:blank"
	b.Title = http.StatusText(b.Status)

	h := w.Header()
	h.Set("Content-Type", ContentType)
	if b.RetryAfter > 0 {
		h.Set("Retry-After", strconv.FormatInt(b.RetryAfter, 10))
	}
	w.WriteHeader(b.Status)
	_ = json.NewEncoder(w).Encode(b) // the status is sent; a failed write cannot be reported
}

// WriteNotImplemented renders the 501 of an operation that has no handler yet. The problem has no
// code: the SDD §10 catalogue has none for it, and no operation of the contract answers 501.
func (pw *Writer) WriteNotImplemented(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}{"about:blank", http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented})
}

// unexpected logs err with the request id and returns the generic UNAVAILABLE body, which carries
// no retry hint because the cause is unknown.
func (pw *Writer) unexpected(r *http.Request, err error) body {
	pw.logger.LogAttrs(r.Context(), slog.LevelError, "request failed",
		telemetry.RequestID(requestid.From(r.Context())), telemetry.Err(err))
	return body{Status: http.StatusServiceUnavailable, Code: domain.CodeUnavailable, Detail: unavailableDetail}
}
