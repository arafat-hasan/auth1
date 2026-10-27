package config

import (
	"reflect"
	"sort"
	"strconv"
)

// The configuration schema is read from Config's koanf tags by reflection, so the key paths that
// strict decoding, environment overrides and the example check rely on cannot drift from the
// types.

const tagName = "koanf"

var secretFileType = reflect.TypeFor[SecretFile]()

// isSection reports whether t is a struct whose fields are keys of their own. SecretFile is a
// struct but a single value.
func isSection(t reflect.Type) bool {
	return t.Kind() == reflect.Struct && t != secretFileType
}

// fields calls fn with the key and value of each tagged field of the struct v.
func fields(v reflect.Value, fn func(key string, f reflect.Value)) {
	t := v.Type()
	for i := range t.NumField() {
		if key := t.Field(i).Tag.Get(tagName); key != "" {
			fn(key, v.Field(i))
		}
	}
}

// flatten returns v's values by dotted key path. Sections and maps of sections (such as
// identifiers) are walked; lists and other maps are single values.
func flatten(v any) map[string]any {
	out := map[string]any{}
	flattenValue(reflect.ValueOf(v), "", out)
	return out
}

func flattenValue(v reflect.Value, prefix string, out map[string]any) {
	switch {
	case isSection(v.Type()):
		fields(v, func(key string, f reflect.Value) { flattenValue(f, join(prefix, key), out) })
	case v.Kind() == reflect.Map && isSection(v.Type().Elem()):
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		for _, k := range keys {
			flattenValue(v.MapIndex(k), join(prefix, k.String()), out)
		}
	default:
		out[prefix] = v.Interface()
	}
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// unknownKeys returns a problem for each key in raw, a parsed configuration file, that the schema
// does not define. Values of the wrong shape are left to decoding, which reports them.
func unknownKeys(raw map[string]any) []*Problem {
	var out []*Problem
	unknownIn(raw, reflect.TypeFor[Config](), "", &out)
	return out
}

func unknownIn(raw any, t reflect.Type, prefix string, out *[]*Problem) {
	switch {
	case isSection(t):
		m, ok := raw.(map[string]any)
		if !ok {
			return
		}
		known := map[string]reflect.Type{}
		for i := range t.NumField() {
			if key := t.Field(i).Tag.Get(tagName); key != "" {
				known[key] = t.Field(i).Type
			}
		}
		for key, v := range m {
			ft, ok := known[key]
			if !ok {
				*out = append(*out, &Problem{Path: join(prefix, key), Message: "unknown key"})
				continue
			}
			unknownIn(v, ft, join(prefix, key), out)
		}
	case t.Kind() == reflect.Map && isSection(t.Elem()):
		m, ok := raw.(map[string]any)
		if !ok {
			return
		}
		for key, v := range m {
			unknownIn(v, t.Elem(), join(prefix, key), out)
		}
	case t.Kind() == reflect.Slice && isSection(t.Elem()):
		list, ok := raw.([]any)
		if !ok {
			return
		}
		for i, v := range list {
			unknownIn(v, t.Elem(), prefix+"["+strconv.Itoa(i)+"]", out)
		}
	}
}

// sectionMapPaths returns the paths of maps of sections (such as identifiers). A file that sets
// one replaces its default entries instead of merging with them.
func sectionMapPaths() []string {
	var out []string
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for i := range t.NumField() {
			f := t.Field(i)
			key := f.Tag.Get(tagName)
			switch {
			case key == "":
			case isSection(f.Type):
				walk(f.Type, join(prefix, key))
			case f.Type.Kind() == reflect.Map && isSection(f.Type.Elem()):
				out = append(out, join(prefix, key))
			}
		}
	}
	walk(reflect.TypeFor[Config](), "")
	return out
}
