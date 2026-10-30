package apitest

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	verrors "github.com/pb33f/libopenapi-validator/errors"
	"github.com/pb33f/libopenapi-validator/schema_validation"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
)

// TB is the part of testing.TB that the harness reports through.
type TB interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// Validator checks requests and responses against api/openapi.yaml.
type Validator struct {
	v     validator.Validator
	model *v3.Document
	// schemaMu serialises CheckSchema: the model builds its schemas lazily, unsafely for
	// concurrent use.
	schemaMu sync.Mutex
}

// New loads api/openapi.yaml, failing t if the document does not load.
func New(t TB) *Validator {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("apitest: cannot locate the source file")
		return nil
	}
	spec, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("apitest: read the contract: %v", err)
		return nil
	}
	doc, err := libopenapi.NewDocument(spec)
	if err != nil {
		t.Fatalf("apitest: parse the contract: %v", err)
		return nil
	}
	v, errs := validator.NewValidator(doc)
	if len(errs) > 0 {
		t.Fatalf("apitest: build the validator: %v", errs)
		return nil
	}
	model, err := doc.BuildV3Model()
	if err != nil {
		t.Fatalf("apitest: build the model: %v", err)
		return nil
	}
	return &Validator{v: v, model: &model.Model}
}

// Serve serves req with h and checks both against the contract, reporting each violation through
// t.Errorf. The handler may read the request body; the returned response's body is unread.
func (v *Validator) Serve(t TB, h http.Handler, req *http.Request) *http.Response {
	t.Helper()
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			t.Fatalf("apitest: read the request body: %v", err)
		}
	}
	withBody := func() *http.Request {
		r := req.Clone(req.Context())
		r.Body = io.NopCloser(bytes.NewReader(body))
		return r
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, withBody())
	resp := rec.Result()
	v.Check(t, withBody(), resp)
	return resp
}

// Check checks req and resp against the contract, reporting each violation through t.Errorf. It
// reads both bodies and puts back resp's.
func (v *Validator) Check(t TB, req *http.Request, resp *http.Response) {
	t.Helper()
	var reqBody []byte
	if req.Body != nil {
		var err error
		if reqBody, err = io.ReadAll(req.Body); err != nil {
			t.Fatalf("apitest: read the request body: %v", err)
		}
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("apitest: read the response body: %v", err)
	}
	_ = resp.Body.Close()
	fresh := func() *http.Request {
		r := req.Clone(req.Context())
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
		return r
	}

	if ok, errs := v.v.ValidateHttpRequestSync(fresh()); !ok {
		for _, e := range errs {
			t.Errorf("request %s %s: %s", req.Method, req.URL.Path, describe(e))
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	if ok, errs := v.v.ValidateHttpResponse(fresh(), resp); !ok {
		for _, e := range errs {
			t.Errorf("response to %s %s (%d): %s", req.Method, req.URL.Path, resp.StatusCode, describe(e))
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
}

// CheckSchema checks body, JSON, against the contract's component schema named schema, reporting
// each violation through t.Errorf. It is for payloads no operation of auth1 serves, such as the
// outbound DeliveryRequest.
func (v *Validator) CheckSchema(t TB, schema string, body []byte) {
	t.Helper()
	v.schemaMu.Lock()
	defer v.schemaMu.Unlock()
	proxy := v.model.Components.Schemas.GetOrZero(schema)
	if proxy == nil {
		t.Errorf("apitest: the contract has no schema %s", schema)
		return
	}
	s := proxy.Schema()
	if s == nil {
		t.Errorf("apitest: build schema %s: %v", schema, proxy.GetBuildError())
		return
	}
	if ok, errs := schema_validation.NewSchemaValidator().ValidateSchemaBytesWithVersion(s, body, 3.1); !ok {
		for _, e := range errs {
			t.Errorf("schema %s: %s", schema, describe(e))
		}
	}
}

// describe renders a validation error with its schema failures.
func describe(e *verrors.ValidationError) string {
	var b strings.Builder
	b.WriteString(e.Message)
	if e.Reason != "" {
		fmt.Fprintf(&b, ": %s", e.Reason)
	}
	for _, f := range e.SchemaValidationErrors {
		fmt.Fprintf(&b, "\n\t%s: %s", f.FieldPath, f.Reason)
	}
	return b.String()
}
