package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// rootPackage is how the module's root package appears in module-relative paths.
const rootPackage = "."

// layerRules lists the restricted layers. A dependency inside the module breaks a rule when the
// layer has an allowed list that does not cover it, or a denied list that does. Prefixes are
// module-relative. Layers not listed are not restricted.
var layerRules = []struct {
	layer   string
	allowed []string
	denied  []string
}{
	{layer: "internal/domain", allowed: []string{"internal/domain"}},
	{layer: "internal/app", allowed: []string{"internal/domain", "internal/app"}},
	// Adapters and HTTP meet only through app (TDD-08 §2).
	{layer: "internal/adapters", denied: []string{"internal/http"}},
	{layer: "internal/http", denied: []string{"internal/adapters"}},
}

// CheckLayering reports every dependency that breaks the layering rules. deps maps each package
// import path to the import paths it depends on. Violations are sorted and read
// "<package> imports <dependency>", both relative to module ("." is the module root).
func CheckLayering(module string, deps map[string][]string) []string {
	var violations []string
	for pkg, pkgDeps := range deps {
		rel, ok := relative(module, pkg)
		if !ok {
			continue
		}
		for _, rule := range layerRules {
			if !under(rel, rule.layer) {
				continue
			}
			for _, dep := range pkgDeps {
				depRel, ok := relative(module, dep)
				if !ok {
					continue
				}
				if rule.allowed != nil && matchesAny(depRel, rule.allowed) {
					continue
				}
				if rule.allowed == nil && !matchesAny(depRel, rule.denied) {
					continue
				}
				violations = append(violations, rel+" imports "+depRel)
			}
		}
	}
	sort.Strings(violations)
	return violations
}

// ListDeps runs "go list -deps -json ./..." in dir, outside any go.work. It returns the module path
// and, for each package of the module, its transitive dependencies inside the module. Files that
// build constraints leave out of the default build (other tags or platforms) add their direct
// imports, so a constraint cannot hide a dependency. Test files are not included.
func ListDeps(ctx context.Context, dir string) (string, map[string][]string, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-json", "./...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", nil, fmt.Errorf("go list: %w: %s", err, stderr.String())
	}

	type listed struct {
		Dir            string
		ImportPath     string
		Deps           []string
		IgnoredGoFiles []string
		Module         *struct {
			Path string
			Main bool
		}
	}
	var pkgs []listed
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listed
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return "", nil, fmt.Errorf("decode go list output: %w", err)
		}
		pkgs = append(pkgs, p)
	}

	var module string
	for _, p := range pkgs {
		if p.Module != nil && p.Module.Main {
			module = p.Module.Path
			break
		}
	}
	if module == "" {
		return "", nil, errors.New("go list reported no package of the main module")
	}

	deps := make(map[string][]string)
	for _, p := range pkgs {
		if _, ok := relative(module, p.ImportPath); !ok {
			continue
		}
		ignored, err := ignoredImports(p.Dir, p.IgnoredGoFiles)
		if err != nil {
			return "", nil, err
		}
		var own []string
		for _, d := range append(p.Deps, ignored...) {
			if _, ok := relative(module, d); ok {
				own = append(own, d)
			}
		}
		deps[p.ImportPath] = own
	}
	return module, deps, nil
}

// ignoredImports returns the imports of the non-test files in dir that build constraints leave
// out of the default build.
func ignoredImports(dir string, files []string) ([]string, error) {
	var imports []string
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || !strings.HasSuffix(name, ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return nil, fmt.Errorf("import in %s: %w", name, err)
			}
			imports = append(imports, path)
		}
	}
	return imports, nil
}

// relative returns pkg relative to module ("." for the module root), and whether pkg is inside
// module.
func relative(module, pkg string) (string, bool) {
	if pkg == module {
		return rootPackage, true
	}
	return strings.CutPrefix(pkg, module+"/")
}

// under reports whether rel is the package prefix or one of its subpackages.
func under(rel, prefix string) bool {
	return rel == prefix || strings.HasPrefix(rel, prefix+"/")
}

func matchesAny(rel string, prefixes []string) bool {
	for _, p := range prefixes {
		if under(rel, p) {
			return true
		}
	}
	return false
}
