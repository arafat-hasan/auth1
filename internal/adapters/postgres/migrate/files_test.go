package migrate

import (
	"crypto/sha256"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
)

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

func TestLoad(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		got, err := Load(fstest.MapFS{})
		if err != nil || len(got) != 0 {
			t.Fatalf("Load = %v, %v; want none", got, err)
		}
	})

	t.Run("sorted, with contents and checksums", func(t *testing.T) {
		t.Parallel()
		fsys := fstest.MapFS{
			"000002_b.up.sql":   file("create b"),
			"000002_b.down.sql": file("drop b"),
			"000001_a.up.sql":   file("create a"),
			"000001_a.down.sql": file("drop a"),
			"README.md":         file("ignored"),
			"x.go":              file("package x"),
		}
		got, err := Load(fsys)
		if err != nil {
			t.Fatal(err)
		}
		want := []Migration{
			{Version: 1, Name: "a", Up: []byte("create a"), Down: []byte("drop a"), Checksum: sha256.Sum256([]byte("create a"))},
			{Version: 2, Name: "b", Up: []byte("create b"), Down: []byte("drop b"), Checksum: sha256.Sum256([]byte("create b"))},
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("Load (-want +got):\n%s", diff)
		}
		if f := got[0].File(); f != "000001_a.up.sql" {
			t.Errorf("File = %q", f)
		}
	})

	t.Run("missing down file", func(t *testing.T) {
		t.Parallel()
		got, err := Load(fstest.MapFS{"000001_a.up.sql": file("x")})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Down != nil {
			t.Errorf("Load = %+v; want one migration with no down file", got)
		}
	})

	for _, tc := range []struct {
		name  string
		fsys  fstest.MapFS
		names []string
	}{
		{"short number", fstest.MapFS{"1_a.up.sql": file("")}, []string{"1_a.up.sql"}},
		{"upper case name", fstest.MapFS{"000001_A.up.sql": file("")}, []string{"000001_A.up.sql"}},
		{"bad direction", fstest.MapFS{"000001_a.sideways.sql": file("")}, []string{"000001_a.sideways.sql"}},
		{"duplicate version", fstest.MapFS{
			"000001_a.up.sql": file(""), "000001_a.down.sql": file(""),
			"000001_b.up.sql": file(""), "000001_b.down.sql": file(""),
		}, []string{"000001_a", "000001_b"}},
		{"down without up", fstest.MapFS{"000001_a.down.sql": file("")}, []string{"000001_a.down.sql"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(tc.fsys)
			if err == nil {
				t.Fatal("Load succeeded; want an error")
			}
			for _, n := range tc.names {
				if !strings.Contains(err.Error(), n) {
					t.Errorf("error %q does not name %q", err, n)
				}
			}
		})
	}
}
