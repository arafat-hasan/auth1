package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
)

// layerRules lists, for each restricted layer, the only module-relative package prefixes its
// transitive dependencies may have inside the module. Layers not listed are not restricted.
var layerRules = []struct {
	layer   string
	allowed []string
}{
	{layer: "internal/domain", allowed: []string{"internal/domain"}},
	{layer: "internal/app", allowed: []string{"internal/domain", "internal/app"}},
}

// CheckLayering reports every dependency that breaks the layering rules. deps maps each package
// import path to the import paths it depends on. Violations are sorted and read
// "<package> imports <dependency>", both relative to module.
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
				if !ok || allowed(depRel, rule.allowed) {
					continue
				}
				violations = append(violations, rel+" imports "+depRel)
			}
		}
	}
	sort.Strings(violations)
	return violations
}

// ListDeps runs "go list -deps -json ./..." in dir. It returns the main module path and, for each
// package of that module, its transitive dependencies inside the module.
func ListDeps(ctx context.Context, dir string) (string, map[string][]string, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-json", "./...")
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", nil, fmt.Errorf("go list: %w: %s", err, stderr.String())
	}

	type listed struct {
		ImportPath string
		Deps       []string
		Module     *struct {
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
		var own []string
		for _, d := range p.Deps {
			if _, ok := relative(module, d); ok {
				own = append(own, d)
			}
		}
		deps[p.ImportPath] = own
	}
	return module, deps, nil
}

// relative returns pkg relative to module, and whether pkg is inside module.
func relative(module, pkg string) (string, bool) {
	return strings.CutPrefix(pkg, module+"/")
}

// under reports whether rel is the package prefix or one of its subpackages.
func under(rel, prefix string) bool {
	return rel == prefix || strings.HasPrefix(rel, prefix+"/")
}

func allowed(rel string, prefixes []string) bool {
	for _, p := range prefixes {
		if under(rel, p) {
			return true
		}
	}
	return false
}
