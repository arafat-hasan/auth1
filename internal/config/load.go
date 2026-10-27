package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
)

// Load reads the YAML file at path over the defaults, then applies the AUTH1_ variables in environ
// (entries of the form KEY=value, as from os.Environ).
//
// A key with no value (such as a section whose keys are all commented out) keeps its default.
//
// Unknown keys are problems, returned together with the decoded configuration so that a caller
// can also Validate it and report everything at once. A file that cannot be read, parsed or
// decoded gives a nil configuration, with every problem found. Load does not validate.
func Load(path string, environ []string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the operator names the configuration file
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	raw, err := yaml.Parser().Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if raw == nil {
		raw = map[string]any{}
	}
	problems := unknownKeys(raw)
	defaults := defaultsFor(raw)
	dropNulls(raw)

	k := koanf.New(".")
	if err := k.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return nil, fmt.Errorf("load defaults: %w", err)
	}
	if err := k.Load(confmap.Provider(raw, ""), nil); err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	env, envProblems := resolveEnv(environ, scalarPaths())
	problems = append(problems, envProblems...)
	if err := k.Load(confmap.Provider(env, "."), nil); err != nil {
		return nil, fmt.Errorf("load environment: %w", err)
	}

	var cfg Config
	if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		Tag: tagName,
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				numberToDurationHook,
				numberToByteSizeHook,
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.TextUnmarshallerHookFunc(),
			),
			Result:  &cfg,
			TagName: tagName,
		},
	}); err != nil {
		return nil, joinProblems(append(problems, decodeProblems(err)...))
	}
	for i := range cfg.Clients {
		if cfg.Clients[i].MFA == "" {
			cfg.Clients[i].MFA = MFAOptional
		}
	}
	return &cfg, joinProblems(problems)
}

// defaultsFor returns the defaults as a flat map. When raw sets a map of sections, its entries
// replace the default entries: an entry the file names keeps that entry's defaults under the
// values it sets, and a default entry the file does not name is dropped.
func defaultsFor(raw map[string]any) map[string]any {
	defaults := flatten(Default())
	for key, v := range defaults {
		if f, ok := v.(SecretFile); ok {
			defaults[key] = f.Path()
		}
	}
	for _, mapPath := range sectionMapPaths() {
		set, ok := lookup(raw, mapPath)
		if !ok || set == nil {
			continue
		}
		entries, _ := set.(map[string]any)
		for key := range defaults {
			rest, under := strings.CutPrefix(key, mapPath+".")
			if !under {
				continue
			}
			name, _, _ := strings.Cut(rest, ".")
			if _, named := entries[name]; !named {
				delete(defaults, key)
			}
		}
	}
	return defaults
}

// dropNulls removes the keys without a value from the nested maps of m, so that they keep their
// defaults when m is merged over them. Lists are left alone.
func dropNulls(m map[string]any) {
	for key, v := range m {
		switch v := v.(type) {
		case nil:
			delete(m, key)
		case map[string]any:
			dropNulls(v)
		}
	}
}

// lookup finds a dotted path in a nested map.
func lookup(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		next, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = next[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// decodeProblems turns mapstructure's errors into one problem per key path.
func decodeProblems(err error) []*Problem {
	var out []*Problem
	for _, e := range leafErrors(err) {
		var de *mapstructure.DecodeError
		if !errors.As(e, &de) {
			out = append(out, &Problem{Path: "(configuration)", Message: e.Error()})
			continue
		}
		inner := de.Unwrap()
		var nested *mapstructure.DecodeError
		if _, joined := inner.(interface{ Unwrap() []error }); joined || errors.As(inner, &nested) {
			out = append(out, decodeProblems(inner)...)
			continue
		}
		out = append(out, &Problem{Path: de.Name(), Message: inner.Error()})
	}
	return out
}

var (
	durationType = reflect.TypeFor[time.Duration]()
	byteSizeType = reflect.TypeFor[ByteSize]()
)

func isNumber(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// numberToDurationHook refuses a bare number for a duration: 900 would otherwise mean 900ns.
func numberToDurationHook(from, to reflect.Type, data any) (any, error) {
	if to == durationType && from != durationType && isNumber(from.Kind()) {
		return nil, fmt.Errorf("%v is not a duration: use Go duration syntax, such as 15m or 1h30m", data)
	}
	return data, nil
}

// numberToByteSizeHook accepts a whole, non-negative number of bytes.
func numberToByteSizeHook(from, to reflect.Type, data any) (any, error) {
	if to != byteSizeType || from == byteSizeType || !isNumber(from.Kind()) {
		return data, nil
	}
	if v := reflect.ValueOf(data); v.CanInt() && v.Int() >= 0 {
		return ByteSize(v.Int()), nil
	}
	return nil, fmt.Errorf("%v is not a size: use a whole number of bytes or a KiB, MiB or GiB suffix", data)
}
