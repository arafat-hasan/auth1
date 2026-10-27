package guard

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxScanSize is the largest file the product-word scan reads; larger files are not code.
const maxScanSize = 1 << 20

// scanned lists the paths, relative to the repository root, that hold code, default
// configuration and migrations (SDD D-1). Missing paths are skipped.
var scanned = []string{
	"cmd", "internal", "migrations", "api", "test", ".github",
	"go.mod", "Makefile", ".golangci.yml",
}

// ReadWords reads a newline-separated word list. Lines are trimmed and lowercased; blank lines
// and lines starting with "#" are skipped. A list with no words is an error.
func ReadWords(path string) ([]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own word list
	if err != nil {
		return nil, fmt.Errorf("read word list: %w", err)
	}
	var words []string
	for line := range strings.Lines(string(data)) {
		w := strings.ToLower(strings.TrimSpace(line))
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		words = append(words, w)
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("word list %s holds no words", path)
	}
	return words, nil
}

// ScanForWords looks for each word, case-insensitively, in the regular files under root/<path>
// for every entry of paths. Missing paths are skipped, and so are .git directories, files larger
// than 1 MiB and binary files. Findings are sorted and read "<relpath>:<line>: <word>".
func ScanForWords(root string, paths []string, words []string) ([]string, error) {
	var found []string
	for _, p := range paths {
		start := filepath.Join(root, p)
		if _, err := os.Stat(start); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		err := filepath.WalkDir(start, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return fmt.Errorf("relative path of %s: %w", path, err)
			}
			hits, err := scanFile(path, filepath.ToSlash(rel), words)
			if err != nil {
				return err
			}
			found = append(found, hits...)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", p, err)
		}
	}
	sort.Strings(found)
	return found, nil
}

func scanFile(path, rel string, words []string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", rel, err)
	}
	if info.Size() > maxScanSize {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // paths come from walking the repository
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rel, err)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, nil
	}
	var hits []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxScanSize)
	for n := 1; sc.Scan(); n++ {
		line := strings.ToLower(sc.Text())
		for _, w := range words {
			if strings.Contains(line, w) {
				hits = append(hits, fmt.Sprintf("%s:%d: %s", rel, n, w))
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", rel, err)
	}
	return hits, nil
}
