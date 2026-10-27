package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ByteSize is a size in bytes. In configuration it is written as a whole number of bytes,
// optionally followed by KiB, MiB or GiB, for example 64MiB.
type ByteSize int64

// Binary size units.
const (
	KiB ByteSize = 1 << 10
	MiB ByteSize = 1 << 20
	GiB ByteSize = 1 << 30
)

var byteUnits = []struct {
	suffix string
	size   ByteSize
}{
	{"GiB", GiB},
	{"MiB", MiB},
	{"KiB", KiB},
}

// ParseByteSize parses a size such as "64MiB", "1536KiB" or "100". Units are case-sensitive; there
// is no sign, fraction or space.
func ParseByteSize(s string) (ByteSize, error) {
	digits, unit := s, ByteSize(1)
	for _, u := range byteUnits {
		if strings.HasSuffix(s, u.suffix) {
			digits, unit = strings.TrimSuffix(s, u.suffix), u.size
			break
		}
	}
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, fmt.Errorf("invalid size %q: want a whole number with an optional KiB, MiB or GiB suffix", s)
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n > math.MaxInt64/int64(unit) {
		return 0, fmt.Errorf("invalid size %q: too large", s)
	}
	return ByteSize(n) * unit, nil
}

// String formats the size in the largest unit that divides it exactly.
func (b ByteSize) String() string {
	if b != 0 {
		for _, u := range byteUnits {
			if b%u.size == 0 {
				return strconv.FormatInt(int64(b/u.size), 10) + u.suffix
			}
		}
	}
	return strconv.FormatInt(int64(b), 10)
}

// MarshalText implements encoding.TextMarshaler.
func (b ByteSize) MarshalText() ([]byte, error) { return []byte(b.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (b *ByteSize) UnmarshalText(text []byte) error {
	v, err := ParseByteSize(string(text))
	if err != nil {
		return err
	}
	*b = v
	return nil
}
