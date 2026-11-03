package caller

import "strings"

// xfccURI returns the URI of the client certificate that an X-Forwarded-Client-Cert header carries
// (TDD-05 §1): the value of the first URI key of its only element. values are the header's lines.
// It returns false, so the request has no workload identity, for more than one header line or
// more than one element, for no URI or an empty one, and for anything it cannot parse.
//
// An element is key=value pairs separated by ';'; elements are separated by ','. A value may be in
// double quotes, inside which ',', ';' and '=' are literal and a backslash escapes the next
// character; outside quotes a value may hold neither a quote nor a backslash.
func xfccURI(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	s := values[0]
	var uri string
	found := false
	for i := 0; ; {
		key, value, next, ok := xfccPair(s, i)
		if !ok {
			return "", false
		}
		if !found && strings.EqualFold(key, "URI") {
			uri, found = value, true
		}
		if next == len(s) {
			break
		}
		if s[next] == ',' {
			return "", false // a second element
		}
		i = next + 1 // past ';'
	}
	return uri, uri != ""
}

// xfccPair parses the key=value pair of s starting at i. next is the index just after it: len(s),
// or that of the ';' or ',' that ends it.
func xfccPair(s string, i int) (key, value string, next int, ok bool) {
	start := i
	for i < len(s) && s[i] != '=' {
		switch s[i] {
		case ';', ',', '"', '\\':
			return "", "", 0, false
		}
		i++
	}
	if i == start || i == len(s) {
		return "", "", 0, false
	}
	key = s[start:i]
	i++ // past '='
	if i < len(s) && s[i] == '"' {
		var b strings.Builder
		for i++; ; i++ {
			if i == len(s) {
				return "", "", 0, false // unclosed quote
			}
			c := s[i]
			if c == '"' {
				break
			}
			if c == '\\' {
				if i++; i == len(s) {
					return "", "", 0, false
				}
				c = s[i]
			}
			b.WriteByte(c)
		}
		i++ // past the closing quote
		if i < len(s) && s[i] != ';' && s[i] != ',' {
			return "", "", 0, false
		}
		return key, b.String(), i, true
	}
	start = i
	for i < len(s) && s[i] != ';' && s[i] != ',' {
		if s[i] == '"' || s[i] == '\\' {
			return "", "", 0, false
		}
		i++
	}
	return key, s[start:i], i, true
}
