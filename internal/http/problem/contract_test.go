package problem

import (
	"bytes"
	"maps"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.yaml.in/yaml/v3"

	"github.com/arafat-hasan/auth1/internal/domain"
)

// openAPI is the part of api/openapi.yaml these tests read.
type openAPI struct {
	Paths      map[string]map[string]operation `yaml:"paths"`
	Components struct {
		Schemas struct {
			Problem struct {
				Required   []string `yaml:"required"`
				Properties map[string]struct {
					Enum []string `yaml:"enum"`
				} `yaml:"properties"`
			} `yaml:"Problem"`
		} `yaml:"schemas"`
		Responses map[string]any `yaml:"responses"`
	} `yaml:"components"`
}

type operation struct {
	RequestBody any            `yaml:"requestBody"`
	Responses   map[string]any `yaml:"responses"`
}

func loadOpenAPI(t *testing.T) openAPI {
	t.Helper()
	raw, err := os.ReadFile("../../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc openAPI
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestContractCodes checks that the Problem schema's code enum is the domain catalogue.
func TestContractCodes(t *testing.T) {
	t.Parallel()

	schema := loadOpenAPI(t).Components.Schemas.Problem
	var codes []string
	for _, c := range domain.Codes() {
		codes = append(codes, string(c))
	}
	if diff := cmp.Diff(slices.Sorted(slices.Values(schema.Properties["code"].Enum)), slices.Sorted(slices.Values(codes))); diff != "" {
		t.Errorf("Problem.code enum (-contract +domain):\n%s", diff)
	}
}

// TestContractMembers renders a body with every optional member and checks its keys against the
// Problem schema.
func TestContractMembers(t *testing.T) {
	t.Parallel()

	schema := loadOpenAPI(t).Components.Schemas.Problem
	left := 1
	_, body := write(t, &bytes.Buffer{}, &domain.Error{
		Code: domain.CodeValidationFailed, Detail: "d", RetryAfter: time.Second, AttemptsLeft: &left,
		Reasons: []string{"too_short"}, Fields: []domain.FieldError{{Field: "f", Code: "c"}},
	})
	for k := range body {
		if _, ok := schema.Properties[k]; !ok {
			t.Errorf("member %q is not in the Problem schema", k)
		}
	}
	for _, k := range schema.Required {
		if _, ok := body[k]; !ok {
			t.Errorf("required member %q is missing", k)
		}
	}
	t.Logf("schema members: %v", slices.Sorted(maps.Keys(schema.Properties)))
}

// TestContractBodyLimit checks that every operation with a request body documents the 413.
func TestContractBodyLimit(t *testing.T) {
	t.Parallel()

	doc := loadOpenAPI(t)
	if _, ok := doc.Components.Responses["PayloadTooLarge"]; !ok {
		t.Fatal("components/responses/PayloadTooLarge is missing")
	}
	n := 0
	for path, ops := range doc.Paths {
		for method, op := range ops {
			if op.RequestBody == nil {
				continue
			}
			n++
			if _, ok := op.Responses["413"]; !ok {
				t.Errorf("%s %s takes a body but does not list 413", method, path)
			}
		}
	}
	if n == 0 {
		t.Error("found no operation with a request body")
	}
}
