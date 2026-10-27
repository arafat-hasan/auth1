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
	var walk func(error)
	walk = func(err error) {
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			for _, e := range joined.Unwrap() {
				walk(e)
			}
			return
		}
		var p *Problem
		if errors.As(err, &p) {
			out = append(out, p)
		}
	}
	if err != nil {
		walk(err)
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
