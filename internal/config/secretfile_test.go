package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secretContent = "TOPSECRET"

func TestSecretFileCheck(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	writeFile(t, regular, secretContent, 0o600)
	unreadable := filepath.Join(dir, "unreadable")
	writeFile(t, unreadable, secretContent, 0o000)
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
		root    bool // skipped as root, which can read anything
	}{
		{name: "regular file", path: regular},
		{name: "symlink to a regular file", path: link},
		{name: "missing", path: filepath.Join(dir, "missing"), wantErr: true},
		{name: "directory", path: dir, wantErr: true},
		{name: "dangling symlink", path: dangling, wantErr: true},
		{name: "unreadable", path: unreadable, wantErr: true, root: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.root && os.Geteuid() == 0 {
				t.Skip("root can read a mode 000 file")
			}
			err := NewSecretFile(tt.path).check()
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("check(%s): %v", tt.path, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("check(%s): want an error", tt.path)
			}
			if strings.Contains(err.Error(), secretContent) {
				t.Errorf("error %q contains the file's contents", err)
			}
		})
	}
}

func TestSecretFileFormatting(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "key")
	writeFile(t, path, secretContent, 0o600)
	f := NewSecretFile(path)

	if f.Path() != path || !f.IsSet() || NewSecretFile("").IsSet() {
		t.Fatalf("Path/IsSet: got %q, %v", f.Path(), f.IsSet())
	}
	formatted := fmt.Sprintf("%v %s %+v %#v", f, f, f, f) + f.String()
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("loaded", "file", f)
	text, err := f.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"fmt": formatted, "slog": logged.String(), "text": string(text)} {
		if strings.Contains(out, secretContent) {
			t.Errorf("%s output %q contains the file's contents", name, out)
		}
		if !strings.Contains(out, path) {
			t.Errorf("%s output %q does not show the path", name, out)
		}
	}
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
