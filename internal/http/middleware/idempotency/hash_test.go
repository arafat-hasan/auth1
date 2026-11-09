package idempotency

import (
	"bytes"
	"crypto/sha256"
	"math"
	"strconv"
	"testing"

	"github.com/gowebpki/jcs"
)

// TestJCSVectors checks the canonicaliser against RFC 8785: the §3.2.2 example, the §3.2.3
// sorting example and the Appendix B numbers.
func TestJCSVectors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, in, want string }{
		{
			name: "§3.2.2",
			in: `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`,
			want: `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		},
		{
			name: "§3.2.3",
			in: `{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}`,
			want: "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\"," +
				"\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
		},
	} {
		got, err := jcs.Transform([]byte(tc.in))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(got) != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, got, tc.want)
		}
	}

	for _, tc := range []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	} {
		in := strconv.FormatFloat(math.Float64frombits(tc.bits), 'e', -1, 64)
		got, err := jcs.Transform([]byte("[" + in + "]"))
		if err != nil {
			t.Fatalf("%#x (%s): %v", tc.bits, in, err)
		}
		if want := "[" + tc.want + "]"; string(got) != want {
			t.Errorf("%#x (%s): got %s, want %s", tc.bits, in, got, want)
		}
	}
}

func TestRequestHash(t *testing.T) {
	t.Parallel()

	const path = "/v1/accounts/0190a0a0-0000-7000-8000-000000000001/status"
	hash := func(t *testing.T, method, path, body string) []byte {
		t.Helper()
		h, err := RequestHash(method, path, []byte(body))
		if err != nil {
			t.Fatalf("RequestHash(%s, %s, %q): %v", method, path, body, err)
		}
		return h
	}
	base := hash(t, "PUT", path, `{"status":"suspended","reason_code":"fraud","revoke_sessions":true}`)

	want := sha256.Sum256([]byte("PUT\x00" + path + "\x00" + `{"reason_code":"fraud","revoke_sessions":true,"status":"suspended"}`))
	if !bytes.Equal(base, want[:]) {
		t.Errorf("hash = %x, want sha256(method 0x00 path 0x00 JCS(body)) = %x", base, want)
	}

	for _, tc := range []struct {
		name, method, path, body string
		same                     bool
	}{
		{"members reordered", "PUT", path, `{"revoke_sessions":true,"status":"suspended","reason_code":"fraud"}`, true},
		{"whitespace", "PUT", path, "{ \"status\" : \"suspended\",\n\"reason_code\":\"fraud\", \"revoke_sessions\": true }", true},
		{"escaped character", "PUT", path, `{"status":"susp\u0065nded","reason_code":"fraud","revoke_sessions":true}`, true},
		{"another method", "POST", path, `{"status":"suspended","reason_code":"fraud","revoke_sessions":true}`, false},
		{"another account", "PUT", "/v1/accounts/0190a0a0-0000-7000-8000-000000000002/status",
			`{"status":"suspended","reason_code":"fraud","revoke_sessions":true}`, false},
		{"another value", "PUT", path, `{"status":"suspended","reason_code":"fraud","revoke_sessions":false}`, false},
	} {
		if got := hash(t, tc.method, tc.path, tc.body); bytes.Equal(got, base) != tc.same {
			t.Errorf("%s: equal = %v, want %v", tc.name, !tc.same, tc.same)
		}
	}

	if !bytes.Equal(hash(t, "POST", "/a", `{"n":1.0}`), hash(t, "POST", "/a", `{"n":1}`)) {
		t.Error("1.0 and 1 hash differently")
	}
	if bytes.Equal(hash(t, "POST", "/a", ""), hash(t, "POST", "/a", "{}")) {
		t.Error("an empty body and {} hash the same")
	}
	// The fields are separated, so moving bytes between them changes the hash.
	if bytes.Equal(hash(t, "POST", "/a%00b", ""), hash(t, "POST", "/a", `"b"`)) {
		t.Error("a path with %00 collides with another path and body")
	}

	for _, body := range []string{`{"a":1,"a":2}`, "{\"a\":\"\xff\"}", `{"a":1} x`, `{"a":`, `{'a':1}`} {
		if _, err := RequestHash("POST", "/a", []byte(body)); err == nil {
			t.Errorf("RequestHash(%q): no error", body)
		}
	}
}

func FuzzRequestHash(f *testing.F) {
	for _, s := range []string{"", "{}", `{"a":1,"a":2}`, `[1e30, -0, "\u20ac"]`, `{"b":[{"a":null}]}`, "\xff", `{"a":`} {
		f.Add("POST", "/v1/invitations", s)
	}
	f.Fuzz(func(t *testing.T, method, path, body string) {
		got, err := RequestHash(method, path, []byte(body))
		again, againErr := RequestHash(method, path, []byte(body))
		if (err == nil) != (againErr == nil) || !bytes.Equal(got, again) {
			t.Fatalf("not deterministic: %x, %v then %x, %v", got, err, again, againErr)
		}
		if err == nil && len(got) != sha256.Size {
			t.Fatalf("hash of %d bytes", len(got))
		}
	})
}
