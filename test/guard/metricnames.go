package guard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// metricName matches a string literal that names an auth1 metric.
var metricName = regexp.MustCompile(`^auth1_[a-z0-9_]+$`)

// CheckMetricNames reports each metric name in literals that allowed does not list, sorted and
// without repeats. It sees only whole literals: a name built at run time, such as "auth1_" + x,
// passes here and is refused by telemetry.Metrics when the instrument is created.
func CheckMetricNames(literals, allowed []string) []string {
	var unknown []string
	for _, l := range literals {
		if metricName.MatchString(l) && !slices.Contains(allowed, l) && !slices.Contains(unknown, l) {
			unknown = append(unknown, l)
		}
	}
	sort.Strings(unknown)
	return unknown
}

// StringLiterals returns the string literals of the non-test Go files under root, skipping
// testdata, hidden and vendor directories.
func StringLiterals(root string) ([]string, error) {
	var literals []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					literals = append(literals, s)
				}
			}
			return true
		})
		return nil
	})
	return literals, err
}
