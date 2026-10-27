package config

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// envPrefix starts every environment override. AUTH1_TOKENS_REFRESH_IDLE_TTL sets
// tokens.refresh_idle_ttl.
const envPrefix = "AUTH1_"

// envName returns the environment variable that overrides path.
func envName(path string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
}

// scalarPaths returns every key path that an environment variable can set, with its type: the
// single values reachable through sections only. Lists and maps are file-only.
func scalarPaths() map[string]reflect.Type {
	out := map[string]reflect.Type{}
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for i := range t.NumField() {
			f := t.Field(i)
			key := f.Tag.Get(tagName)
			switch {
			case key == "":
			case isSection(f.Type):
				walk(f.Type, join(prefix, key))
			case f.Type.Kind() != reflect.Slice && f.Type.Kind() != reflect.Map:
				out[join(prefix, key)] = f.Type
			}
		}
	}
	walk(reflect.TypeFor[Config](), "")
	return out
}

// resolveEnv returns the overrides in environ by key path. Keys contain underscores, so a variable
// is matched against the variable name of each known path rather than split. A variable that
// matches no path or several, or whose value does not fit its key, is a problem. Variables
// without the AUTH1_ prefix are ignored.
func resolveEnv(environ []string, paths map[string]reflect.Type) (map[string]any, []*Problem) {
	byName := map[string][]string{}
	for path := range paths {
		byName[envName(path)] = append(byName[envName(path)], path)
	}

	values := map[string]any{}
	var problems []*Problem
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, envPrefix) {
			continue
		}
		matches := byName[name]
		switch len(matches) {
		case 0:
			problems = append(problems, &Problem{Path: name, Message: "no configuration key has this environment variable"})
			continue
		case 1:
		default:
			sort.Strings(matches)
			problems = append(problems, &Problem{Path: name, Message: "ambiguous: matches " + strings.Join(matches, " and ")})
			continue
		}
		path := matches[0]
		v, err := envValue(value, paths[path])
		if err != nil {
			problems = append(problems, &Problem{Path: path, Message: fmt.Sprintf("%s: %v", name, err)})
			continue
		}
		values[path] = v
	}
	return values, problems
}

// envValue converts a variable's text to what decoding expects for t, so that a bad value is
// reported against the variable rather than only its key. Files and enums stay strings.
func envValue(value string, t reflect.Type) (any, error) {
	switch {
	case t == durationType:
		d, err := time.ParseDuration(value)
		if err != nil {
			return nil, fmt.Errorf("%q is not a duration: use Go duration syntax, such as 15m or 1h30m", value)
		}
		return d, nil
	case t == byteSizeType:
		return ParseByteSize(value)
	case t == secretFileType || t.Kind() == reflect.String:
		return value, nil
	case t.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("%q is not a boolean", value)
		}
		return b, nil
	case t.Kind() == reflect.Int:
		n, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("%q is not an integer", value)
		}
		return n, nil
	}
	return nil, fmt.Errorf("type %s cannot be set from the environment", t)
}
