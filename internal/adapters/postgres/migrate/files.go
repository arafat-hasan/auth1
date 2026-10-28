package migrate

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
)

// fileName is a migration file's name: a six-digit version, a lower-case name and a direction.
var fileName = regexp.MustCompile(`^(\d{6})_([a-z0-9_]+)\.(up|down)\.sql$`)

// Migration is one numbered migration.
type Migration struct {
	Version  int64
	Name     string
	Up       []byte
	Down     []byte // nil when the down file is missing
	Checksum [sha256.Size]byte
}

// File returns the name of the migration's up file, such as "000001_init.up.sql".
func (m Migration) File() string { return m.base() + ".up.sql" }

// DownFile returns the name of the migration's down file.
func (m Migration) DownFile() string { return m.base() + ".down.sql" }

func (m Migration) base() string { return fmt.Sprintf("%06d_%s", m.Version, m.Name) }

// Load reads the migrations at the root of fsys, sorted by version. Files that are not SQL are
// ignored. A SQL file whose name does not follow the pattern, two migrations with one version, and
// a down file without its up file are errors naming the files. The checksum is the SHA-256 of the
// up file.
func Load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	byVersion := map[int64]*Migration{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || path.Ext(name) != ".sql" {
			continue
		}
		parts := fileName.FindStringSubmatch(name)
		if parts == nil {
			return nil, fmt.Errorf("migration file %s: name is not NNNNNN_<name>.up.sql or .down.sql", name)
		}
		version, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("migration file %s: %w", name, err)
		}
		m, ok := byVersion[version]
		if !ok {
			m = &Migration{Version: version, Name: parts[2]}
			byVersion[version] = m
		} else if m.Name != parts[2] {
			return nil, fmt.Errorf("migrations %s and %06d_%s share version %d", m.base(), version, parts[2], version)
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("migration file %s: %w", name, err)
		}
		if data == nil {
			data = []byte{}
		}
		if parts[3] == "up" {
			m.Up = data
			m.Checksum = sha256.Sum256(data)
		} else {
			m.Down = data
		}
	}

	out := make([]Migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.Up == nil {
			return nil, fmt.Errorf("migration file %s has no up file %s", m.DownFile(), m.File())
		}
		out = append(out, *m)
	}
	slices.SortFunc(out, func(a, b Migration) int { return cmp.Compare(a.Version, b.Version) })
	return out, nil
}
