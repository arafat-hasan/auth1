package guard

import (
	"context"
	"slices"
	"testing"
)

func TestCheckLayeringRules(t *testing.T) {
	t.Parallel()

	const mod = "example.com/m"
	tests := []struct {
		name string
		deps map[string][]string
		want []string
	}{
		{
			name: "domain imports an adapter",
			deps: map[string][]string{mod + "/internal/domain": {mod + "/internal/adapters/postgres"}},
			want: []string{"internal/domain imports internal/adapters/postgres"},
		},
		{
			name: "domain imports a domain subpackage",
			deps: map[string][]string{mod + "/internal/domain": {mod + "/internal/domain/sub"}},
		},
		{
			name: "app imports domain",
			deps: map[string][]string{mod + "/internal/app/account": {mod + "/internal/domain"}},
		},
		{
			name: "app imports http",
			deps: map[string][]string{mod + "/internal/app": {mod + "/internal/http/handlers"}},
			want: []string{"internal/app imports internal/http/handlers"},
		},
		{
			name: "app imports an adapter",
			deps: map[string][]string{mod + "/internal/app": {mod + "/internal/adapters/redis"}},
			want: []string{"internal/app imports internal/adapters/redis"},
		},
		{
			name: "adapter imports app",
			deps: map[string][]string{mod + "/internal/adapters/postgres": {mod + "/internal/app", mod + "/internal/domain"}},
		},
		{
			name: "http imports app",
			deps: map[string][]string{mod + "/internal/http/handlers": {mod + "/internal/app"}},
		},
		{
			name: "domain name prefix is not domain",
			deps: map[string][]string{mod + "/internal/domainx": {mod + "/internal/adapters/redis"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CheckLayering(mod, tt.deps)
			if !slices.Equal(got, tt.want) {
				t.Errorf("CheckLayering = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLayering(t *testing.T) {
	t.Parallel()

	module, deps, err := ListDeps(context.Background(), "../..")
	if err != nil {
		t.Fatalf("list dependencies: %v", err)
	}
	if _, ok := deps[module+"/internal/domain"]; !ok {
		t.Fatalf("go list did not report %s/internal/domain; got %d packages", module, len(deps))
	}
	for _, v := range CheckLayering(module, deps) {
		t.Errorf("layering violation: %s", v)
	}
}

