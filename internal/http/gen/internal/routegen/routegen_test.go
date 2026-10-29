package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const contractPath = "../../../../../api/openapi.yaml"

// fixture is a minimal contract with one person-facing and one service operation; tests replace
// the markers to break it.
const fixture = `openapi: 3.1.0
info: { title: t, version: '1' }
paths:
  /v1/me/sessions/{sessionId}:
    delete:
      operationId: revokeMySession
      SCOPE_ON_PERSON
      security:
        - bearer: []
      responses: { '204': { description: ok } }
  /v1/introspect:
    post:
      operationId: introspectToken
      SERVICE_SCOPE
      security:
        - workload: []
        - serviceToken: []
      responses: { '200': { description: ok } }
  /v1/registrations:
    post:
      operationId: startRegistration
      security: []
      responses: { '201': { description: ok } }
webhooks:
  deliveryRequest:
    post:
      operationId: submitDeliveryRequest
      security:
        - workload: []
      responses: { '202': { description: ok } }
components:
  securitySchemes:
    bearer: { type: http, scheme: bearer }
    workload: { type: mutualTLS }
    serviceToken:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: /v1/oauth/token
          scopes:
            tokens:introspect: Introspect access tokens
`

func spec(personScope, serviceScope string) []byte {
	r := strings.NewReplacer("SCOPE_ON_PERSON", personScope, "SERVICE_SCOPE", serviceScope)
	return []byte(r.Replace(fixture))
}

func TestOperations(t *testing.T) {
	t.Parallel()

	ok := []op{
		{ID: "introspectToken", Method: "POST", Path: "/v1/introspect", Scope: "tokens:introspect", Security: []string{"serviceToken", "workload"}},
		{ID: "revokeMySession", Method: "DELETE", Path: "/v1/me/sessions/{sessionId}", Security: []string{"bearer"}},
		{ID: "startRegistration", Method: "POST", Path: "/v1/registrations", Security: []string{}},
	}
	tests := []struct {
		name    string
		spec    []byte
		want    []op
		wantErr []string // substrings of the error; nil for none
	}{
		{name: "valid", spec: spec("", "x-auth1-scope: tokens:introspect"), want: ok},
		{name: "service operation without a scope", spec: spec("", ""),
			wantErr: []string{"introspectToken", "x-auth1-scope"}},
		{name: "scope on a person-facing operation", spec: spec("x-auth1-scope: tokens:introspect", "x-auth1-scope: tokens:introspect"),
			wantErr: []string{"revokeMySession", "x-auth1-scope"}},
		{name: "undeclared scope", spec: spec("", "x-auth1-scope: tokens:mint"),
			wantErr: []string{"introspectToken", "tokens:mint"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := operations(tt.spec)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("operations: %v", err)
				}
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("operations (-want +got):\n%s", diff)
				}
				return
			}
			if err == nil {
				t.Fatalf("operations: no error, want one containing %q", tt.wantErr)
			}
			for _, s := range tt.wantErr {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("error %q does not contain %q", err, s)
				}
			}
		})
	}
}

// TestContract runs the generator's rules on api/openapi.yaml, and checks that removing one
// service operation's scope fails them.
func TestContract(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := operations(raw)
	if err != nil {
		t.Fatalf("operations: %v", err)
	}
	var found bool
	for _, o := range ops {
		if o.ID == "introspectToken" {
			found = true
			if diff := cmp.Diff(op{ID: "introspectToken", Method: "POST", Path: "/v1/introspect", Scope: "tokens:introspect",
				Security: []string{"serviceToken", "workload"}}, o); diff != "" {
				t.Errorf("introspectToken (-want +got):\n%s", diff)
			}
		}
		if o.ID == "submitDeliveryRequest" {
			t.Error("the webhook submitDeliveryRequest is listed; auth1 sends it, it does not serve it")
		}
	}
	if !found {
		t.Fatal("introspectToken is missing")
	}

	broken := bytes.Replace(raw, []byte("      x-auth1-scope: tokens:introspect\n"), nil, 1)
	if bytes.Equal(broken, raw) {
		t.Fatal("the contract has no x-auth1-scope line for introspectToken")
	}
	if _, err := operations(broken); err == nil || !strings.Contains(err.Error(), "introspectToken") {
		t.Errorf("without introspectToken's scope: err = %v, want one naming introspectToken", err)
	}
}

// TestRoutesDeterministic checks that the generated source is stable, so that the CI staleness
// check does not flap, and that it carries the generated-code header.
func TestRoutesDeterministic(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	var outs [2][]byte
	for i := range outs {
		ops, err := operations(raw)
		if err != nil {
			t.Fatal(err)
		}
		if outs[i], err = routes(ops); err != nil {
			t.Fatalf("routes: %v", err)
		}
	}
	if !bytes.Equal(outs[0], outs[1]) {
		t.Error("two runs generated different source")
	}
	if want := "// Code generated by routegen from api/openapi.yaml. DO NOT EDIT.\n"; !bytes.HasPrefix(outs[0], []byte(want)) {
		t.Errorf("source does not start with %q", want)
	}
	if !bytes.Contains(outs[0], []byte(`"introspectToken":`)) {
		t.Error("source has no entry for introspectToken")
	}
}

// TestStub checks the stub source: one method per operation, in the strict server's names.
func TestStub(t *testing.T) {
	t.Parallel()

	src, err := stub([]op{{ID: "introspectToken"}, {ID: "getMe"}})
	if err != nil {
		t.Fatalf("stub: %v", err)
	}
	for _, want := range []string{
		"// Code generated by routegen from api/openapi.yaml. DO NOT EDIT.\n",
		"func (Stub) IntrospectToken(context.Context, IntrospectTokenRequestObject) (IntrospectTokenResponseObject, error) {\n\treturn nil, ErrNotImplemented\n}",
		"func (Stub) GetMe(context.Context, GetMeRequestObject) (GetMeResponseObject, error) {",
	} {
		if !bytes.Contains(src, []byte(want)) {
			t.Errorf("stub source does not contain %q:\n%s", want, src)
		}
	}
}
