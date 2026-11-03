package caller

import (
	"strings"
	"testing"
)

const spiffe = "spiffe://cluster.local/ns/billing/sa/billing"

func TestXFCCURI(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		values []string
		want   string // "" for no identity
	}{
		{"one element", []string{`By=spiffe://cluster.local/ns/auth1/sa/auth1;Hash=abc;URI=` + spiffe}, spiffe},
		{"URI only", []string{"URI=" + spiffe}, spiffe},
		{"key case", []string{"uri=" + spiffe}, spiffe},
		{"quoted subject with separators", []string{`Hash=abc;Subject="CN=a,OU=b;c";URI=` + spiffe}, spiffe},
		{"escaped quote", []string{`Subject="O=\"x\", CN=y";URI=` + spiffe}, spiffe},
		{"quoted URI", []string{`URI="` + spiffe + `"`}, spiffe},
		{"first of two URIs", []string{"URI=" + spiffe + ";URI=spiffe://other"}, spiffe},
		{"two elements", []string{"URI=" + spiffe + ",URI=spiffe://cluster.local/ns/edge/sa/edge"}, ""},
		{"two elements, the second without URI", []string{"URI=" + spiffe + ",Hash=abc"}, ""},
		{"two header lines", []string{"URI=" + spiffe, "URI=spiffe://other"}, ""},
		{"trailing comma", []string{"URI=" + spiffe + ","}, ""},
		{"no URI", []string{"Hash=abc;DNS=billing"}, ""},
		{"empty URI", []string{"URI=;Hash=abc"}, ""},
		{"empty quoted URI", []string{`URI=""`}, ""},
		{"unclosed quote", []string{`Subject="CN=a;URI=` + spiffe}, ""},
		{"text after closing quote", []string{`Subject="CN=a"x;URI=` + spiffe}, ""},
		{"pair without =", []string{"Hash;URI=" + spiffe}, ""},
		{"empty pair", []string{"Hash=abc;;URI=" + spiffe}, ""},
		{"empty header", []string{""}, ""},
		{"no header", nil, ""},
	} {
		got, ok := xfccURI(tc.values)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: xfccURI(%q) = %q, %v; want %q", tc.name, tc.values, got, ok, tc.want)
		}
	}
}

func FuzzXFCCURI(f *testing.F) {
	for _, s := range []string{
		"URI=" + spiffe,
		`By=spiffe://a;Hash=abc;Subject="CN=a,OU=b;c";URI=` + spiffe,
		`Subject="O=\"x\", CN=y";URI=` + spiffe,
		"URI=" + spiffe + ",URI=spiffe://b",
		"URI=" + spiffe + "\nURI=spiffe://b",
		`URI="`, `URI="\`, `"`, `\`, `=`, `;`, `,`, `;;`, `URI=a;URI=`, `"a"=b`, `URI=""`, `URI="a"b`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		values := strings.Split(header, "\n")
		got, ok := xfccURI(values)
		if ok != (got != "") {
			t.Fatalf("xfccURI(%q) = %q, %v: ok must mean a non-empty URI", values, got, ok)
		}
		if again, againOK := xfccURI(values); again != got || againOK != ok {
			t.Fatalf("not deterministic: %q, %v then %q, %v", got, ok, again, againOK)
		}
		if ok && len(values) != 1 {
			t.Fatalf("xfccURI accepted %d header lines", len(values))
		}
	})
}
