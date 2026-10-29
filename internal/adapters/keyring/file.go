package keyring

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// The algorithms a key may have (D-12).
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// minRSABits is the smallest RSA key RS256 accepts (TDD-04 §5.1).
const minRSABits = 2048

// State is a key's state in the keyring file.
type State string

// The states of TDD-04 §5.1.
const (
	StateNext    State = "next"
	StateActive  State = "active"
	StateRetired State = "retired"
)

// Key is one validated key of the keyring file. It never prints its private part: every fmt verb,
// slog and its String and GoString give only the alg, the state and the kid.
type Key struct {
	Alg    string
	State  State
	Kid    string           // RFC 7638 thumbprint of Public
	Public crypto.PublicKey // *rsa.PublicKey or *ecdsa.PublicKey

	private crypto.Signer // *rsa.PrivateKey or *ecdsa.PrivateKey
}

// String returns "alg state kid".
func (k Key) String() string { return k.Alg + " " + string(k.State) + " " + k.Kid }

// GoString implements fmt.GoStringer, without the key material.
func (k Key) GoString() string { return "keyring.Key{" + k.String() + "}" }

// Format implements fmt.Formatter for every verb, without the key material.
func (k Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// MarshalJSON implements json.Marshaler, without the key material.
func (k Key) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"alg": k.Alg, "state": string(k.State), "kid": k.Kid})
}

// LogValue implements slog.LogValuer, without the key material.
func (k Key) LogValue() slog.Value {
	return slog.GroupValue(slog.String("alg", k.Alg), slog.String("state", string(k.State)), slog.String("kid", k.Kid))
}

// File is a validated keyring file.
type File struct {
	Path string // the keyring file
	Keys []Key  // in the file's order
}

// Active returns the file's one active key.
func (f *File) Active() Key {
	for _, k := range f.Keys {
		if k.State == StateActive {
			return k
		}
	}
	panic("keyring: a validated file without an active key")
}

// String returns the path and the keys, without key material.
func (f File) String() string {
	var b bytes.Buffer
	b.WriteString(f.Path)
	b.WriteString(" [")
	for i, k := range f.Keys {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(k.String())
	}
	b.WriteString("]")
	return b.String()
}

// GoString implements fmt.GoStringer, without the key material.
func (f File) GoString() string { return "keyring.File{" + f.String() + "}" }

// Format implements fmt.Formatter for every verb, without the key material.
func (f File) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, f.String()) }

// LogValue implements slog.LogValuer, without the key material.
func (f File) LogValue() slog.Value {
	return slog.GroupValue(slog.String("path", f.Path), slog.Any("keys", f.Keys))
}

// entry is one key as the file states it.
type entry struct {
	Alg            string `yaml:"alg"`
	State          State  `yaml:"state"`
	PrivateKeyFile string `yaml:"private_key_file"`
}

// source is the keyring file and the PEM files it names, as read, before validation. Digest covers
// all of them, so a PEM swapped behind an unchanged keyring file is a change.
type source struct {
	path    string
	entries []entry
	pems    [][]byte // per entry; nil when the entry names no file
	digest  [sha256.Size]byte
}

// Load reads the keyring file at path and the PEM files it names, and validates them (TDD-04 §5.1).
// Every error names the file and the entry by its position (keys[i]), never the key.
func Load(path string) (*File, error) {
	src, err := read(path)
	if err != nil {
		return nil, err
	}
	return src.parse()
}

// read reads the keyring file, strictly (an unknown field or a second YAML document is an error),
// and each PEM file. A relative private_key_file is relative to the keyring file's directory.
func read(path string) (*source, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the configured keyring file
	if err != nil {
		return nil, fmt.Errorf("signing keyring %s: %w", path, err)
	}
	var doc struct {
		Keys []entry `yaml:"keys"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("signing keyring %s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("signing keyring %s: more than one YAML document", path)
	}
	h := sha256.New()
	writeChunk(h, raw)
	src := &source{path: path, entries: doc.Keys, pems: make([][]byte, len(doc.Keys))}
	var errs []error
	for i, e := range doc.Keys {
		if e.PrivateKeyFile == "" {
			errs = append(errs, entryError(path, i, "private_key_file is required"))
			continue
		}
		p := e.PrivateKeyFile
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(path), p)
		}
		b, err := os.ReadFile(p) //nolint:gosec // a PEM file the keyring names
		if err != nil {
			errs = append(errs, entryError(path, i, "%v", err))
			continue
		}
		src.pems[i] = b
		writeChunk(h, []byte(p))
		writeChunk(h, b)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	h.Sum(src.digest[:0])
	return src, nil
}

// writeChunk writes b to h behind its length, so chunk boundaries cannot shift.
func writeChunk(h io.Writer, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

// entryError is a validation failure of keys[i] of the keyring file at path.
func entryError(path string, i int, format string, args ...any) error {
	return fmt.Errorf("signing keyring %s: keys[%d]: %s", path, i, fmt.Sprintf(format, args...))
}

// parse validates the source and builds the keys: alg and state known, the key fits its alg, no
// key twice, exactly one active key (I-6). Every failure is reported.
func (s *source) parse() (*File, error) {
	if len(s.entries) == 0 {
		return nil, fmt.Errorf("signing keyring %s: no keys", s.path)
	}
	var errs []error
	f := &File{Path: s.path}
	seen := map[string]int{}
	active := 0
	for i, e := range s.entries {
		switch e.State {
		case StateNext, StateRetired:
		case StateActive:
			active++
		default:
			errs = append(errs, entryError(s.path, i, "state %q is not next, active or retired", e.State))
		}
		k, err := parseKey(e.Alg, s.pems[i])
		if err != nil {
			errs = append(errs, entryError(s.path, i, "%s", err))
			continue
		}
		k.State = e.State
		if j, dup := seen[k.Kid]; dup {
			errs = append(errs, entryError(s.path, i, "the same key as keys[%d]", j))
			continue
		}
		seen[k.Kid] = i
		f.Keys = append(f.Keys, k)
	}
	if active != 1 {
		errs = append(errs, fmt.Errorf("signing keyring %s: %d active keys; exactly one is required", s.path, active))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return f, nil
}

// parseKey parses one PEM private key and checks it against alg. Its errors never hold key
// material.
func parseKey(alg string, pemBytes []byte) (Key, error) {
	if alg != AlgRS256 && alg != AlgES256 {
		return Key{}, fmt.Errorf("alg %q is not RS256 or ES256", alg)
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return Key{}, errors.New("private_key_file is not PEM")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return Key{}, errors.New("private_key_file holds more than one PEM block")
	}
	var (
		priv any
		err  error
	)
	switch block.Type {
	case "PRIVATE KEY":
		priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		priv, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return Key{}, fmt.Errorf("PEM block %q is not PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY", block.Type)
	}
	if err != nil {
		return Key{}, fmt.Errorf("private_key_file: cannot parse the %s", block.Type)
	}

	k := Key{Alg: alg}
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		if alg != AlgRS256 {
			return Key{}, fmt.Errorf("an RSA key; %s needs an EC P-256 key", alg)
		}
		if bits := p.N.BitLen(); bits < minRSABits {
			return Key{}, fmt.Errorf("an RSA key of %d bits; RS256 needs at least %d", bits, minRSABits)
		}
		k.Public, k.private = &p.PublicKey, p
	case *ecdsa.PrivateKey:
		if alg != AlgES256 {
			return Key{}, fmt.Errorf("an EC key; %s needs an RSA key", alg)
		}
		if p.Curve != elliptic.P256() {
			return Key{}, fmt.Errorf("an EC key on %s; ES256 needs P-256", p.Curve.Params().Name)
		}
		k.Public, k.private = &p.PublicKey, p
	default:
		return Key{}, fmt.Errorf("a %T key; %s needs %s", priv, alg, map[string]string{AlgRS256: "an RSA key", AlgES256: "an EC P-256 key"}[alg])
	}
	if k.Kid, err = thumbprint(k.Public); err != nil {
		return Key{}, err
	}
	return k, nil
}
