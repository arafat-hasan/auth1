package config

import (
	"errors"
	"sort"
)

// Problem is one thing wrong with a configuration, at a key path such as tokens.access_ttl or
// clients[0].origins[1] (or, for an environment variable, the variable's name).
type Problem struct {
	Path    string
	Message string
}

// Error returns "path: message".
func (p *Problem) Error() string { return p.Path + ": " + p.Message }

// Problems returns every *Problem in err, which may be joined with errors.Join.
func Problems(err error) []*Problem {
	var out []*Problem
	for _, e := range leafErrors(err) {
		var p *Problem
		if errors.As(e, &p) {
			out = append(out, p)
		}
	}
	return out
}

// leafErrors returns the errors joined in err, recursively: err itself when it joins none, and
// nothing for a nil err.
func leafErrors(err error) []error {
	if err == nil {
		return nil
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return []error{err}
	}
	var out []error
	for _, e := range joined.Unwrap() {
		out = append(out, leafErrors(e)...)
	}
	return out
}

// joinProblems sorts problems by path and joins them, or returns nil when there are none.
func joinProblems(problems []*Problem) error {
	if len(problems) == 0 {
		return nil
	}
	sort.SliceStable(problems, func(i, j int) bool { return problems[i].Path < problems[j].Path })
	errs := make([]error, len(problems))
	for i, p := range problems {
		errs[i] = p
	}
	return errors.Join(errs...)
}
