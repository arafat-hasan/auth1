package session

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretRedacts(t *testing.T) {
	t.Parallel()

	// A value long enough that no timestamp or other output contains it by chance.
	const value = "918273645091827364"
	s := Secret(value)
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		out = append(out, fmt.Sprintf(verb, s))
	}
	out = append(out, s.String(), s.GoString())

	var buf bytes.Buffer
	noTime := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}
	slog.New(slog.NewJSONHandler(&buf, noTime)).Info("m", "token", s)
	slog.New(slog.NewTextHandler(&buf, noTime)).Info("m", "token", s)
	out = append(out, buf.String())

	j, err := json.Marshal(struct{ S Secret }{s})
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, string(j))

	for _, o := range out {
		if strings.Contains(o, value) || strings.Contains(o, fmt.Sprintf("%x", value)) ||
			strings.Contains(o, base64.StdEncoding.EncodeToString([]byte(value))) || !strings.Contains(o, "[redacted]") {
			t.Errorf("formatted secret %q: want [redacted] and no trace of the value", o)
		}
	}
}
