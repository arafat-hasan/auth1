package crypto_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
)

// keyBytes returns 32 bytes starting at first and counting up.
func keyBytes(first byte) []byte {
	b := make([]byte, crypto.KeySize)
	for i := range b {
		b[i] = first + byte(i)
	}
	return b
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func mustKey(t *testing.T, first byte) crypto.Key {
	t.Helper()
	k, err := crypto.ParseKey([]byte(b64(keyBytes(first))))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseKey(t *testing.T) {
	t.Parallel()
	raw := keyBytes(1)
	for _, tt := range []struct {
		name, in string
		ok       bool
	}{
		{"valid", b64(raw), true},
		{"surrounding white space", " \n\t" + b64(raw) + "\n\n", true},
		{"not base64", "not base64 at all!!", false},
		{"unpadded", strings.TrimRight(b64(raw), "="), false},
		{"31 bytes", b64(raw[:31]), false},
		{"33 bytes", b64(append(raw, 0)), false},
		{"empty", "", false},
		{"white space only", "  \n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k, err := crypto.ParseKey([]byte(tt.in))
			if !tt.ok {
				if err == nil {
					t.Fatal("ParseKey accepted it")
				}
				if in := strings.TrimSpace(tt.in); in != "" && strings.Contains(err.Error(), in) {
					t.Errorf("error %q contains the input", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseKey: %v", err)
			}
			if !bytes.Equal(k.Bytes(), raw) {
				t.Error("Bytes differ from the decoded key")
			}
		})
	}
}

func TestKeyBytesIsACopy(t *testing.T) {
	t.Parallel()
	k := mustKey(t, 1)
	b := k.Bytes()
	b[0] ^= 0xff
	if k.Bytes()[0] != 1 {
		t.Error("changing the result of Bytes changed the key")
	}
}

func TestLoadKeyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "good.key")
	if err := os.WriteFile(good, []byte(b64(keyBytes(1))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.LoadKeyFile(good); err != nil {
		t.Errorf("LoadKeyFile(good): %v", err)
	}
	short := filepath.Join(dir, "short.key")
	if err := os.WriteFile(short, []byte(b64(keyBytes(1)[:16])), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{short, filepath.Join(dir, "missing.key")} {
		_, err := crypto.LoadKeyFile(path)
		if err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("LoadKeyFile(%s) = %v, want an error naming the file", path, err)
		}
	}
}

// formatted returns v under every fmt verb that could show bytes, and as an slog attribute
// through the JSON and text handlers.
func formatted(v any) []string {
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d"} {
		outs = append(outs, fmt.Sprintf(verb, v))
	}
	for _, h := range []func(*bytes.Buffer) slog.Handler{
		func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
	} {
		var buf bytes.Buffer
		slog.New(h(&buf)).Info("msg", "v", v)
		outs = append(outs, buf.String())
	}
	return outs
}

// byteList prints each byte of b with format, joined by sep: "1 2 3" as %v prints a byte array,
// "0x1, 0x2, 0x3" as %#v does.
func byteList(b []byte, format, sep string) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf(format, c)
	}
	return strings.Join(parts, sep)
}

// assertRedacted fails if any formatting of v shows one of the keys: raw, in hex or base64, or
// byte by byte as fmt prints a byte array.
func assertRedacted(t *testing.T, v any, keys ...[]byte) {
	t.Helper()
	for _, out := range formatted(v) {
		for _, k := range keys {
			for _, form := range []string{
				string(k), hex.EncodeToString(k), strings.ToUpper(hex.EncodeToString(k)), b64(k),
				byteList(k[:8], "%d", " "), byteList(k[:8], "%#x", ", "),
			} {
				if strings.Contains(out, form) {
					t.Errorf("output %q shows a key", out)
				}
			}
		}
	}
}

func TestKeyRedacted(t *testing.T) {
	t.Parallel()
	k := mustKey(t, 1)
	type exported struct{ K crypto.Key }
	type unexported struct{ k crypto.Key }
	for name, v := range map[string]any{
		"value":      k,
		"pointer":    &k,
		"exported":   exported{K: k},
		"unexported": unexported{k: k},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertRedacted(t, v, keyBytes(1))
		})
	}
}
