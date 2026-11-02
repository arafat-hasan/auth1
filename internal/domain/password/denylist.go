package password

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// maxLine is the longest deny-list line accepted, in bytes.
const maxLine = 64 << 10

// DenyList is the set of refused passwords (passwords.deny_list_file), held in their comparison
// form. It is safe for concurrent use once parsed.
type DenyList struct {
	set map[string]struct{}
}

// ParseDenyList reads one password per line (TDD-03 §2): a line ending, "\n" or "\r\n", is
// removed and other white space kept; empty lines are skipped; there is no comment syntax. It
// refuses a line that is not UTF-8 or is longer than 64 KiB. Errors name the line number, never
// its contents.
func ParseDenyList(r io.Reader) (*DenyList, error) {
	d := &DenyList{set: make(map[string]struct{})}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), maxLine+2) // room for the line ending
	n := 0
	for s.Scan() {
		n++
		line := s.Bytes()
		switch {
		case len(line) == 0:
			continue
		case len(line) > maxLine:
			return nil, fmt.Errorf("line %d: longer than %d bytes", n, maxLine)
		case !utf8.Valid(line):
			return nil, fmt.Errorf("line %d: not UTF-8", n)
		}
		d.set[string(fold(line))] = struct{}{}
	}
	if err := s.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("line %d: longer than %d bytes", n+1, maxLine)
		}
		return nil, fmt.Errorf("line %d: %w", n+1, err)
	}
	return d, nil
}

// Len returns the number of distinct refused passwords.
func (d *DenyList) Len() int { return len(d.set) }

// contains reports whether a password in comparison form is listed.
func (d *DenyList) contains(folded []byte) bool {
	_, ok := d.set[string(folded)]
	return ok
}
