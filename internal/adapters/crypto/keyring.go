package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Keyring states. StateActive is the one key that encrypts; the other state, given to
// ParseKeyring, names the keys kept only to decrypt or verify.
const (
	StateActive  = "active"
	StateDecrypt = "decrypt" // the field keyring's other state (TDD-01 §3.1)
	StateVerify  = "verify"  // the pepper keyring's other state (TDD-03 §1.1)
)

// Keyring is an immutable set of keys with ids, exactly one of them active (TDD-01 §3.1,
// TDD-08 §3.1). It is safe for concurrent use. Formatted or logged, it shows ids and states, never
// key bytes.
type Keyring struct {
	entries []keyEntry // by id
	active  int        // index into entries
}

// keyEntry is one key of a keyring.
type keyEntry struct {
	id    uint16
	state string
	key   Key
}

// KeyringSource gives the keyring to use now. A *Keyring is its own source; a *WatchedKeyring
// gives the latest valid one it has loaded.
type KeyringSource interface {
	Current() *Keyring
}

// keyringFile is the keyring file's shape: a "keys:" list, as the signing keyring (TDD-04 §5.1).
type keyringFile struct {
	Keys []struct {
		ID    *int64 `yaml:"id"`
		Key   string `yaml:"key"`
		State string `yaml:"state"`
	} `yaml:"keys"`
}

// yamlLine finds the line number in a YAML error, which is all of the error that is shown: its
// text may quote the file, and so a key.
var yamlLine = regexp.MustCompile(`line (\d+)`)

// ParseKeyring parses a keyring file: a "keys:" list of {id, key, state}, where id is from 1 to
// 65535 and unique, key is the standard base64 of 32 bytes, used once, and state is "active" or
// otherState, with exactly one "active". Unknown fields are refused. Errors name the entry and the
// reason, never a key. The pepper keyring (TDD-03 §1.1) has the same shape with another
// otherState.
func ParseKeyring(data []byte, otherState string) (*Keyring, error) {
	if otherState == "" || otherState == StateActive {
		return nil, fmt.Errorf("keyring: invalid other state %q", otherState)
	}
	var f keyringFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		msg := "keyring is not valid YAML of the expected shape"
		if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
			msg += " (line " + m[1] + ")"
		}
		return nil, errors.New(msg)
	}
	if len(f.Keys) == 0 {
		return nil, errors.New("keyring has no keys")
	}

	k := &Keyring{active: -1}
	var problems []string
	actives := 0
	for i, e := range f.Keys {
		bad := func(format string, args ...any) {
			problems = append(problems, fmt.Sprintf("keys[%d]: ", i)+fmt.Sprintf(format, args...))
		}
		if e.ID == nil || *e.ID < 1 || *e.ID > 65535 {
			bad("id must be from 1 to 65535")
			continue
		}
		id := uint16(*e.ID)
		if e.State != StateActive && e.State != otherState {
			bad("state must be %q or %q", StateActive, otherState)
			continue
		}
		key, err := ParseKey([]byte(e.Key))
		if err != nil {
			bad("%v", err)
			continue
		}
		if slices.ContainsFunc(k.entries, func(o keyEntry) bool { return o.id == id }) {
			bad("id %d is used twice", id)
			continue
		}
		if j := slices.IndexFunc(k.entries, func(o keyEntry) bool { return o.key.equal(key) }); j >= 0 {
			bad("the key of id %d is used twice", k.entries[j].id)
			continue
		}
		if e.State == StateActive {
			actives++
		}
		k.entries = append(k.entries, keyEntry{id: id, state: e.State, key: key})
	}
	switch {
	case len(problems) > 0:
	case actives == 0:
		problems = append(problems, "keyring has no active key")
	case actives > 1:
		problems = append(problems, "keyring has several active keys")
	}
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "; "))
	}
	slices.SortFunc(k.entries, func(a, b keyEntry) int { return int(a.id) - int(b.id) })
	k.active = slices.IndexFunc(k.entries, func(e keyEntry) bool { return e.state == StateActive })
	return k, nil
}

// LoadKeyring reads and parses a keyring file. Errors name the file, never a key.
func LoadKeyring(path, otherState string) (*Keyring, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path comes from the configuration
	if err != nil {
		return nil, fmt.Errorf("read keyring: %w", err)
	}
	defer clear(data)
	k, err := ParseKeyring(data, otherState)
	if err != nil {
		return nil, fmt.Errorf("keyring file %s: %w", path, err)
	}
	return k, nil
}

// Active returns the active key and its id.
func (k *Keyring) Active() (uint16, Key) {
	e := k.entries[k.active]
	return e.id, e.key
}

// Lookup returns the key with id, active or not.
func (k *Keyring) Lookup(id uint16) (Key, bool) {
	for _, e := range k.entries {
		if e.id == id {
			return e.key, true
		}
	}
	return Key{}, false
}

// Current returns k, so a fixed keyring is a KeyringSource.
func (k *Keyring) Current() *Keyring { return k }

// String lists the ids and states: "keyring(decrypt 1, active 2)".
func (k Keyring) String() string {
	parts := make([]string, len(k.entries))
	for i, e := range k.entries {
		parts[i] = fmt.Sprintf("%s %d", e.state, e.id)
	}
	return "keyring(" + strings.Join(parts, ", ") + ")"
}

// GoString is String.
func (k Keyring) GoString() string { return k.String() }

// Format writes String for every verb.
func (k Keyring) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// LogValue implements slog.LogValuer: String.
func (k Keyring) LogValue() slog.Value { return slog.StringValue(k.String()) }

// MarshalText implements encoding.TextMarshaler: String.
func (k Keyring) MarshalText() ([]byte, error) { return []byte(k.String()), nil }
