package telemetry

import (
	"log/slog"
	"reflect"
	"slices"
	"strings"
)

// Redacted replaces every redacted value in logs.
const Redacted = "[REDACTED]"

// redactedNames are the keys whose values are never logged (TDD-08 §5.1, SDD §14), lower case.
var redactedNames = map[string]bool{
	"authorization": true, "cookie": true, "set-cookie": true,
	"password": true, "code": true, "token": true, "secret": true,
	"email": true, "phone": true, "value": true, "handle": true, "recovery_code": true,
}

// redactedSuffixes mark further keys whose values are never logged, such as db_password.
var redactedSuffixes = []string{"_password", "_token", "_secret"}

// redactedKey reports whether a value logged under key must be redacted. The match ignores case.
func redactedKey(key string) bool {
	k := strings.ToLower(key)
	if redactedNames[k] {
		return true
	}
	for _, s := range redactedSuffixes {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}

// redact replaces a's value when its key, or the key of any group around it, is redacted. A map
// with string keys, of any type (http.Header and url.Values included), becomes a group, so that
// the handler checks its keys too.
func redact(groups []string, a slog.Attr) slog.Attr {
	if redactedKey(a.Key) || slices.ContainsFunc(groups, redactedKey) {
		return slog.String(a.Key, Redacted)
	}
	if a.Value.Kind() != slog.KindAny {
		return a
	}
	if g, ok := mapGroup(a.Value.Any()); ok {
		return slog.Attr{Key: a.Key, Value: g}
	}
	return a
}

// mapGroup turns v, when it is a map whose key type has the underlying type string, into a group
// value with its entries sorted by key. It reports false for any other value.
func mapGroup(v any) (slog.Value, bool) {
	m := reflect.ValueOf(v)
	if m.Kind() != reflect.Map || m.Type().Key().Kind() != reflect.String {
		return slog.Value{}, false
	}
	attrs := make([]slog.Attr, 0, m.Len())
	for it := m.MapRange(); it.Next(); {
		attrs = append(attrs, slog.Any(it.Key().String(), it.Value().Interface()))
	}
	slices.SortFunc(attrs, func(a, b slog.Attr) int { return strings.Compare(a.Key, b.Key) })
	return slog.GroupValue(attrs...), true
}
