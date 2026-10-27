package telemetry

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRedactedKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key  string
		want bool
	}{
		{"authorization", true}, {"Authorization", true}, {"AUTHORIZATION", true},
		{"cookie", true}, {"Cookie", true},
		{"set-cookie", true}, {"SET-COOKIE", true}, {"Set-Cookie", true},
		{"password", true}, {"code", true}, {"token", true}, {"secret", true},
		{"email", true}, {"phone", true}, {"value", true}, {"handle", true},
		{"recovery_code", true}, {"Recovery_Code", true},
		{"db_password", true}, {"refresh_token", true}, {"client_secret", true}, {"Client_Secret", true},

		{"account_id", false}, {"passwords", false}, {"token_type", false}, {"codes", false},
		{"request_id", false}, {"caller", false}, {"x-auth-token", false}, {"secrets", false},
		{"_tokens", false}, {"", false},
	}
	for _, tt := range tests {
		if got := redactedKey(tt.key); got != tt.want {
			t.Errorf("redactedKey(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

// redactedKeys are every key the handler must redact: the TDD-08 §5.1 list and a key for each
// suffix.
var redactedKeys = []string{
	"Authorization", "Cookie", "Set-Cookie", "password", "code", "token", "secret", "email", "phone",
	"value", "handle", "recovery_code", "db_password", "refresh_token", "client_secret",
}

// namedMap is a map type of its own, which the handler must still see into.
type namedMap map[string]string

type withSecret struct {
	Name string
	Key  Secret
}

// TestRedaction logs every redacted key in every position the handler sees, and a value of a
// secret-holding type, and checks that none of the values reaches the output (done-when, #5).
func TestRedaction(t *testing.T) {
	t.Parallel()

	n := 0
	sentinel := func() string { n++; return fmt.Sprintf("sentinel-%d", n) }
	attrs := func() []any {
		var out []any
		for _, k := range redactedKeys {
			out = append(out, slog.String(k, sentinel()))
		}
		return out
	}
	header := http.Header{}
	strMap := map[string]string{}
	listMap := map[string][]string{}
	anyMap := map[string]any{}
	query := url.Values{}
	named := namedMap{}
	for _, k := range redactedKeys {
		header.Set(k, sentinel())
		strMap[k] = sentinel()
		listMap[k] = []string{sentinel()}
		anyMap[k] = sentinel()
		query.Set(k, sentinel())
		named[k] = sentinel()
	}
	strMap["kept"] = "keep-me"

	var buf bytes.Buffer
	l := slog.New(NewHandler(&buf, "svc", "v1"))
	ctx := context.Background()
	l.InfoContext(ctx, "top", attrs()...)
	l.WithGroup("g").InfoContext(ctx, "group", attrs()...)
	l.InfoContext(ctx, "nested", slog.Group("outer", slog.Group("inner", attrs()...)))
	l.With(attrs()...).InfoContext(ctx, "with")
	l.WithGroup("g").With(attrs()...).InfoContext(ctx, "group with")
	l.InfoContext(ctx, "maps",
		slog.Any("header", header), slog.Any("strings", strMap),
		slog.Any("lists", listMap), slog.Any("any", anyMap),
		slog.Any("query", query), slog.Any("named", named))
	l.InfoContext(ctx, "group key", slog.Group("password", slog.String("inner", "sentinel-x")))
	l.InfoContext(ctx, "secret type", slog.Any("k", Secret("sentinel-s")),
		slog.Any("struct", withSecret{Name: "keep-me", Key: Secret("sentinel-t")}))

	out := buf.String()
	if strings.Contains(out, "sentinel-") {
		t.Errorf("output contains a redacted value:\n%s", out)
	}
	if !strings.Contains(out, "keep-me") {
		t.Errorf("output lost a harmless value:\n%s", out)
	}
	if got, want := strings.Count(out, Redacted), 5*len(redactedKeys)+len(redactedKeys)*6+1+2; got < want {
		t.Errorf("output has %d %s markers, want at least %d:\n%s", got, Redacted, want, out)
	}
}
