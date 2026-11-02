package contract

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.yaml.in/yaml/v3"

	"github.com/arafat-hasan/auth1/internal/domain/password"
)

// TestPasswordReasons: the reasons password.Check returns are exactly the contract's enum of
// Problem.reasons, in the same order.
func TestPasswordReasons(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas struct {
				Problem struct {
					Properties struct {
						Reasons struct {
							Items struct {
								Enum []string `yaml:"enum"`
							} `yaml:"items"`
						} `yaml:"reasons"`
					} `yaml:"properties"`
				} `yaml:"Problem"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range password.Reasons() {
		got = append(got, string(r))
	}
	if diff := cmp.Diff(doc.Components.Schemas.Problem.Properties.Reasons.Items.Enum, got); diff != "" {
		t.Errorf("password.Reasons() against the contract (-contract +code):\n%s", diff)
	}
}
