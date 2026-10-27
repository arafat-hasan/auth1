package telemetry

import (
	"log/slog"
	"net/http"
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
// of strings (http.Header included) becomes a group, so that the handler checks its keys too.
func redact(groups []string, a slog.Attr) slog.Attr {
	if redactedKey(a.Key) || slices.ContainsFunc(groups, redactedKey) {
		return slog.String(a.Key, Redacted)
	}
	if a.Value.Kind() != slog.KindAny {
		return a
	}
	switch m := a.Value.Any().(type) {
	case http.Header:
		return slog.Attr{Key: a.Key, Value: mapGroup(m)}
	case map[string][]string:
		return slog.Attr{Key: a.Key, Value: mapGroup(m)}
	case map[string]string:
		return slog.Attr{Key: a.Key, Value: mapGroup(m)}
	case map[string]any:
		return slog.Attr{Key: a.Key, Value: mapGroup(m)}
	}
	return a
}

// mapGroup turns m into a group value with its entries sorted by key.
func mapGroup[V any](m map[string]V) slog.Value {
	attrs := make([]slog.Attr, 0, len(m))
	for k, v := range m {
		attrs = append(attrs, slog.Any(k, v))
	}
	slices.SortFunc(attrs, func(a, b slog.Attr) int { return strings.Compare(a.Key, b.Key) })
	return slog.GroupValue(attrs...)
}
