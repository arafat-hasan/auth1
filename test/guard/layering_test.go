package guard

import (
	"context"
	"os"
	"path/filepath"
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
			name: "http imports an adapter",
			deps: map[string][]string{mod + "/internal/http/handlers": {mod + "/internal/app", mod + "/internal/adapters/postgres"}},
			want: []string{"internal/http/handlers imports internal/adapters/postgres"},
		},
		{
			name: "adapter imports http",
			deps: map[string][]string{mod + "/internal/adapters/redis": {mod + "/internal/http/middleware"}},
			want: []string{"internal/adapters/redis imports internal/http/middleware"},
		},
		{
			name: "adapter imports another adapter",
			deps: map[string][]string{mod + "/internal/adapters/postgres": {mod + "/internal/adapters/crypto"}},
		},
		{
			name: "domain imports the module root",
			deps: map[string][]string{mod + "/internal/domain": {mod}},
			want: []string{"internal/domain imports ."},
		},
		{
			name: "domain name prefix is not domain",
			deps: map[string][]string{mod + "/internal/domainx": {mod + "/internal/adapters/redis"}},
		},
		{
			name: "app imports telemetry",
			deps: map[string][]string{mod + "/internal/app/x": {mod + "/internal/telemetry"}},
			want: []string{"internal/app/x imports internal/telemetry"},
		},
		{
			name: "domain imports telemetry",
			deps: map[string][]string{mod + "/internal/domain": {mod + "/internal/telemetry"}},
			want: []string{"internal/domain imports internal/telemetry"},
		},
		{
			name: "telemetry imports config",
			deps: map[string][]string{mod + "/internal/telemetry": {mod + "/internal/config"}},
		},
		{
			name: "telemetry imports app",
			deps: map[string][]string{mod + "/internal/telemetry": {mod + "/internal/app"}},
			want: []string{"internal/telemetry imports internal/app"},
		},
		{
			name: "telemetry imports http",
			deps: map[string][]string{mod + "/internal/telemetry": {mod + "/internal/http/middleware"}},
			want: []string{"internal/telemetry imports internal/http/middleware"},
		},
		{
			name: "edges and workers import telemetry",
			deps: map[string][]string{
				mod + "/internal/http/middleware":   {mod + "/internal/telemetry"},
				mod + "/internal/adapters/postgres": {mod + "/internal/telemetry"},
				mod + "/internal/worker":            {mod + "/internal/telemetry"},
			},
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

// writeTree writes files (slash-separated paths relative to root) under root.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestListDepsSeesConstrainedFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":                           "module example.com/m\n\ngo 1.27\n",
		"internal/domain/doc.go":           "package domain\n",
		"internal/domain/tagged.go":        "//go:build integration\n\npackage domain\n\nimport _ \"example.com/m/internal/adapters/postgres\"\n",
		"internal/domain/tagged_test.go":   "//go:build integration\n\npackage domain\n\nimport _ \"example.com/m/internal/http\"\n",
		"internal/adapters/postgres/pg.go": "package postgres\n",
		"internal/http/http.go":            "package http\n",
	})

	module, deps, err := ListDeps(context.Background(), dir)
	if err != nil {
		t.Fatalf("list dependencies: %v", err)
	}
	got := CheckLayering(module, deps)
	want := []string{"internal/domain imports internal/adapters/postgres"}
	if !slices.Equal(got, want) {
		t.Errorf("CheckLayering = %q, want %q", got, want)
	}
}

func TestListDepsIgnoresWorkspace(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.work":                     "go 1.27\n\nuse (\n\t./m\n\t./dep\n)\n",
		"dep/go.mod":                  "module example.com/dep\n\ngo 1.27\n",
		"dep/dep.go":                  "package dep\n",
		"m/go.mod":                    "module example.com/m\n\ngo 1.27\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ../dep\n",
		"m/internal/domain/domain.go": "package domain\n\nimport _ \"example.com/dep\"\n",
	})

	module, deps, err := ListDeps(context.Background(), filepath.Join(dir, "m"))
	if err != nil {
		t.Fatalf("list dependencies: %v", err)
	}
	if module != "example.com/m" {
		t.Errorf("module = %q, want %q", module, "example.com/m")
	}
	if _, ok := deps["example.com/m/internal/domain"]; !ok {
		t.Errorf("deps has no example.com/m/internal/domain: %v", deps)
	}
}
