package guard

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The word planted below is a nonsense fixture, not a product word.
const plantedWord = "zorblax"

func TestReadWords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content *string
		want    []string
		wantErr bool
	}{
		{name: "normalises lines", content: ptr("Foo\r\n\n# comment\n  BAR  \n"), want: []string{"foo", "bar"}},
		{name: "empty file", content: ptr("\n# only a comment\n"), wantErr: true},
		{name: "missing file", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "words.txt")
			if tt.content != nil {
				writeFile(t, path, *tt.content)
			}
			got, err := ReadWords(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReadWords error = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ReadWords = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScanFindsPlantedWord(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "internal", "x", "a.go"), "package x\n\nconst s = \"Zorblax\"\n")
	writeFile(t, filepath.Join(root, "internal", "x", "b.go"), "package x\n")
	writeFile(t, filepath.Join(root, "docs", "notes.md"), plantedWord+"\n")

	got, err := ScanForWords(root, []string{"internal", "migrations"}, []string{plantedWord})
	if err != nil {
		t.Fatalf("ScanForWords: %v", err)
	}
	want := []string{"internal/x/a.go:3: " + plantedWord}
	if !slices.Equal(got, want) {
		t.Errorf("ScanForWords = %q, want %q", got, want)
	}
}

func TestScanCleanTree(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "internal", "x", "b.go"), "package x\n")

	got, err := ScanForWords(root, []string{"internal", "migrations"}, []string{plantedWord})
	if err != nil {
		t.Fatalf("ScanForWords: %v", err)
	}
	if got != nil {
		t.Errorf("ScanForWords = %q, want nil", got)
	}
}

func TestProductWords(t *testing.T) {
	t.Parallel()

	path := os.Getenv("AUTH1_PRODUCT_WORDS_FILE")
	if path == "" {
		t.Skip("AUTH1_PRODUCT_WORDS_FILE not set; product-word guard skipped")
	}
	words, err := ReadWords(path)
	if err != nil {
		t.Fatalf("read product words: %v", err)
	}
	found, err := ScanForWords("../..", scanned, words)
	if err != nil {
		t.Fatalf("scan for product words: %v", err)
	}
	for _, f := range found {
		t.Errorf("product word: %s", f)
	}
}

func ptr(s string) *string { return &s }

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
