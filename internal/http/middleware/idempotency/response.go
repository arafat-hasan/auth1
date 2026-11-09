package idempotency

import (
	"bytes"
	"errors"
	"net/http"

	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/domain"
	"github.com/arafat-hasan/auth1/internal/http/problem"
)

// Render returns the response write sends, for app.Idempotency.Run's render callback: the status
// (200 when write sets none), the Content-Type and the body. Only those are stored and replayed
// (TDD-05 §4): other headers, Location and Retry-After among them, are dropped, so an idempotent
// operation must not answer with them. write is a strict response's Visit method, or anything
// writing a response; when it fails, Render returns a 500 and its error, and Run stores nothing.
func Render(write func(w http.ResponseWriter) error) (app.IdempotentResponse, error) {
	rec := &recorder{header: http.Header{}}
	if err := write(rec); err != nil {
		return app.IdempotentResponse{Status: http.StatusInternalServerError}, err
	}
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	var body []byte
	if rec.body.Len() > 0 {
		body = bytes.Clone(rec.body.Bytes())
	}
	return app.IdempotentResponse{Status: rec.status, ContentType: rec.header.Get("Content-Type"), Body: body}, nil
}

// RenderError is Render of the problem pw writes for a refusal: a *domain.Error, or an
// *http.MaxBytesError. Any other error renders as a bare 503 without being written or logged:
// Run stores nothing for it and returns it, and the handler writes it, logged once.
func RenderError(pw *problem.Writer, r *http.Request, err error) (app.IdempotentResponse, error) {
	var (
		de *domain.Error
		me *http.MaxBytesError
	)
	if !errors.As(err, &de) && !errors.As(err, &me) {
		return app.IdempotentResponse{Status: http.StatusServiceUnavailable}, nil
	}
	return Render(func(w http.ResponseWriter) error {
		pw.Write(w, r, err)
		return nil
	})
}

// Write sends resp, as Render captured it or as Run replays it.
func Write(w http.ResponseWriter, resp app.IdempotentResponse) error {
	if resp.ContentType != "" {
		w.Header().Set("Content-Type", resp.ContentType)
	}
	w.WriteHeader(resp.Status)
	if len(resp.Body) == 0 {
		return nil
	}
	_, err := w.Write(resp.Body)
	return err
}

// Response is a response to send through the strict server: a handler returns it, wrapped in a
// one-method type naming the operation's Visit method, e.g.
//
//	type setStatusResponse struct{ idempotency.Response }
//
//	func (r setStatusResponse) VisitSetAccountStatusResponse(w http.ResponseWriter) error { return r.Write(w) }
type Response struct {
	app.IdempotentResponse
}

// Write sends the response.
func (r Response) Write(w http.ResponseWriter) error { return Write(w, r.IdempotentResponse) }

// recorder is the http.ResponseWriter Render captures into.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(b)
}
