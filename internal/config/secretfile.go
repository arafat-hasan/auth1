package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// SecretFile names a file that holds a secret (TDD-08 §4). It holds only the path: configuration
// never carries secret values, and formatting or logging a SecretFile shows the path alone. The
// packages that use a secret read the file themselves.
type SecretFile struct {
	path string
}

// NewSecretFile returns a SecretFile for path. An empty path means the file is not configured.
func NewSecretFile(path string) SecretFile { return SecretFile{path: path} }

// Path returns the file's path.
func (f SecretFile) Path() string { return f.path }

// IsSet reports whether a path is configured.
func (f SecretFile) IsSet() bool { return f.path != "" }

// String returns the path.
func (f SecretFile) String() string { return f.path }

// LogValue implements slog.LogValuer: the path only.
func (f SecretFile) LogValue() slog.Value { return slog.StringValue(f.path) }

// MarshalText implements encoding.TextMarshaler.
func (f SecretFile) MarshalText() ([]byte, error) { return []byte(f.path), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (f *SecretFile) UnmarshalText(text []byte) error {
	f.path = string(text)
	return nil
}

// check reports whether the file is a readable regular file, following symlinks. It opens the
// file to prove it can be read, but reads nothing.
func (f SecretFile) check() error {
	info, err := os.Stat(f.path)
	if err != nil {
		return fileError(err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", f.path)
	}
	file, err := os.Open(f.path)
	if err != nil {
		return fileError(err)
	}
	return file.Close()
}

// fileError describes a file-system error without its operation noise.
func fileError(err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("%s: %w", pathErr.Path, pathErr.Err)
	}
	return err
}
