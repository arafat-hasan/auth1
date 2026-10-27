package config

import (
	"reflect"
	"sort"
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
