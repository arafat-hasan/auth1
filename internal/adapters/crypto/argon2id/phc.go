package argon2id

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/arafat-hasan/auth1/internal/app"
)

// Sizes of the salt and the hash (TDD-03 §1.1).
const (
	saltSize = 16
	hashSize = 32
)

// Bounds on the parameters, of a stored hash or of the configuration. They keep a corrupt row from
// asking for unbounded memory or time; Argon2 itself needs at least 8 KiB per lane.
const (
	maxMemoryKiB   = 1 << 20 // 1 GiB
	maxIterations  = 16
	maxParallelism = 16
)

// phcPrefix is the algorithm and version part of every PHC string (Argon2 version 0x13).
const phcPrefix = "$argon2id$v=19$"

// b64 is the PHC strings' base64: standard alphabet, no padding, canonical trailing bits only.
var b64 = base64.RawStdEncoding.Strict()

// Params are the Argon2id cost parameters.
type Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

// validate checks p against the bounds: 8·Parallelism ≤ MemoryKiB ≤ 1 GiB, 1 ≤ Iterations ≤ 16,
// 1 ≤ Parallelism ≤ 16.
func (p Params) validate() error {
	switch {
	case p.Parallelism < 1 || p.Parallelism > maxParallelism:
		return fmt.Errorf("parallelism must be from 1 to %d", maxParallelism)
	case p.Iterations < 1 || p.Iterations > maxIterations:
		return fmt.Errorf("iterations must be from 1 to %d", maxIterations)
	case p.MemoryKiB < 8*uint32(p.Parallelism) || p.MemoryKiB > maxMemoryKiB:
		return fmt.Errorf("memory must be from 8 KiB per lane to %d KiB", maxMemoryKiB)
	}
	return nil
}

// phc is a parsed Argon2id PHC string.
type phc struct {
	params Params
	salt   [saltSize]byte
	hash   [hashSize]byte
}

// encode returns $argon2id$v=19$m=<KiB>,t=<n>,p=<n>$<salt>$<hash> (TDD-03 §1.2).
func (v phc) encode() string {
	return fmt.Sprintf("%sm=%d,t=%d,p=%d$%s$%s", phcPrefix, v.params.MemoryKiB, v.params.Iterations,
		v.params.Parallelism, b64.EncodeToString(v.salt[:]), b64.EncodeToString(v.hash[:]))
}

// invalid returns an ErrPasswordHashInvalid error with a reason that quotes nothing of the input.
func invalid(reason string) error { return fmt.Errorf("%w: %s", app.ErrPasswordHashInvalid, reason) }

// parsePHC parses a string in exactly encode's form: version 19, the parameters m, t and p in that
// order as decimal without sign or leading zeros and within Params' bounds, a 16-byte salt and a
// 32-byte hash. Bounds are checked before anything is allocated for the hash.
func parsePHC(s string) (phc, error) {
	var v phc
	rest, ok := strings.CutPrefix(s, phcPrefix)
	if !ok {
		return v, invalid("not an Argon2id version 19 PHC string")
	}
	parts := strings.Split(rest, "$")
	if len(parts) != 3 {
		return v, invalid("not three fields after the version")
	}
	fields := strings.Split(parts[0], ",")
	if len(fields) != 3 {
		return v, invalid("parameters are not m, t and p")
	}
	var nums [3]uint32
	for i, name := range []string{"m=", "t=", "p="} {
		digits, ok := strings.CutPrefix(fields[i], name)
		if !ok {
			return v, invalid("parameters are not m, t and p")
		}
		n, err := decimal(digits)
		if err != nil {
			return v, invalid("parameter " + name[:1] + " is not a canonical decimal")
		}
		nums[i] = n
	}
	if nums[2] > maxParallelism {
		return v, invalid("parameters out of bounds")
	}
	v.params = Params{MemoryKiB: nums[0], Iterations: nums[1], Parallelism: uint8(nums[2])} //nolint:gosec // nums[2] ≤ maxParallelism, checked above
	if err := v.params.validate(); err != nil {
		return v, invalid("parameters out of bounds")
	}
	if err := decodeExact(v.salt[:], parts[1]); err != nil {
		return v, invalid("salt is not " + strconv.Itoa(saltSize) + " bytes of unpadded base64")
	}
	if err := decodeExact(v.hash[:], parts[2]); err != nil {
		return v, invalid("hash is not " + strconv.Itoa(hashSize) + " bytes of unpadded base64")
	}
	return v, nil
}

// decimal parses a uint32 written in decimal digits only, without a leading zero.
func decimal(s string) (uint32, error) {
	if s == "" || len(s) > 10 || (s[0] == '0' && len(s) > 1) || strings.Trim(s, "0123456789") != "" {
		return 0, strconv.ErrSyntax
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err //nolint:gosec // ParseUint bounds it to 32 bits
}

// decodeExact decodes s into dst, which it must fill exactly.
func decodeExact(dst []byte, s string) error {
	if len(s) != b64.EncodedLen(len(dst)) {
		return strconv.ErrSyntax
	}
	n, err := b64.Decode(dst, []byte(s))
	if err != nil || n != len(dst) {
		return strconv.ErrSyntax
	}
	return nil
}
