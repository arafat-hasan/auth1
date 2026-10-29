package flow

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestNewOTP(t *testing.T) {
	t.Parallel()

	// 250…255 are skipped; every other byte b gives the digit b % 10.
	r := bytes.NewReader([]byte{249, 250, 255, 0, 9, 100, 7, 13, 251, 252, 253, 254})
	got, err := NewOTP(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "909073" {
		t.Errorf("NewOTP = %q, want %q", got, "909073")
	}
}

func TestNewOTPLength(t *testing.T) {
	t.Parallel()

	for _, n := range []int{6, 8} {
		got, err := NewOTP(rand.Reader, n)
		if err != nil || len(got) != n || strings.Trim(string(got), "0123456789") != "" {
			t.Errorf("NewOTP(%d) = %q, %v; want %d digits", n, got, err, n)
		}
	}
	for _, n := range []int{5, 0, -1} {
		if got, err := NewOTP(rand.Reader, n); !errors.Is(err, ErrOTPLength) || got != nil {
			t.Errorf("NewOTP(%d) = %q, %v; want nil, ErrOTPLength", n, got, err)
		}
	}
}

func TestNewOTPReadError(t *testing.T) {
	t.Parallel()

	failing := errors.New("no entropy")
	if got, err := NewOTP(io.MultiReader(bytes.NewReader([]byte{1, 2}), errReader{failing}), 6); !errors.Is(err, failing) || got != nil {
		t.Errorf("NewOTP over a failing reader = %q, %v; want nil and the reader's error", got, err)
	}
	if got, err := NewOTP(bytes.NewReader([]byte{1, 2, 3}), 6); err == nil || got != nil {
		t.Errorf("NewOTP over a short reader = %q, %v; want nil and an error", got, err)
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// chiSquareLimit is the χ² critical value for 9 degrees of freedom (10 digits) at α = 10⁻⁶. A
// uniform source exceeds it once in a million runs, so the test is not flaky; byte % 10 without
// rejection scores about 366 over 10⁶ digits, so modulo bias is still caught.
const chiSquareLimit = 44.81

const draws = 1_000_000

// chiSquare returns the χ² statistic of the digit counts of s against a uniform distribution.
func chiSquare(s []byte) float64 {
	var counts [10]float64
	for _, c := range s {
		counts[c-'0']++
	}
	want := float64(len(s)) / 10
	var x float64
	for _, n := range counts {
		x += (n - want) * (n - want) / want
	}
	return x
}

// TestOTPUniform checks that OTP digits drawn from crypto/rand are uniform: a chi-square test over
// 10⁶ digits.
func TestOTPUniform(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("10⁶ draws")
	}

	digits, err := NewOTP(rand.Reader, draws)
	if err != nil {
		t.Fatal(err)
	}
	if x := chiSquare(digits); x > chiSquareLimit {
		t.Errorf("χ² = %.2f over %d digits, above %.2f (α = 10⁻⁶): the digits are not uniform", x, draws, chiSquareLimit)
	}

	t.Run("modulo bias fails", func(t *testing.T) {
		t.Parallel()
		raw := make([]byte, draws)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		for i, b := range raw {
			raw[i] = '0' + b%10
		}
		if x := chiSquare(raw); x <= chiSquareLimit {
			t.Errorf("χ² = %.2f for byte %% 10, want above %.2f: the test cannot see modulo bias", x, chiSquareLimit)
		}
	})
}

func TestNewLinkTokenAndHandle(t *testing.T) {
	t.Parallel()

	raw := bytes.Repeat([]byte{0xfb}, 32) // 0xfb… encodes with '-' and '_' in base64url
	for name, gen := range map[string]func(io.Reader) (Secret, error){"NewLinkToken": NewLinkToken, "NewHandle": NewHandle} {
		got, err := gen(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 43 || bytes.ContainsAny(got, "=+/") {
			t.Errorf("%s = %q, want 43 base64url characters without padding", name, got)
		}
		dec, err := base64.RawURLEncoding.DecodeString(string(got))
		if err != nil || !bytes.Equal(dec, raw) {
			t.Errorf("%s decodes to %x, %v; want the reader's 32 bytes", name, dec, err)
		}

		failing := errors.New("no entropy")
		if got, err := gen(errReader{failing}); !errors.Is(err, failing) || got != nil {
			t.Errorf("%s over a failing reader = %q, %v", name, got, err)
		}
		if got, err := gen(bytes.NewReader(raw[:31])); err == nil || got != nil {
			t.Errorf("%s over 31 bytes = %q, %v; want an error", name, got, err)
		}
	}
}

func TestSecretRedacts(t *testing.T) {
	t.Parallel()

	// A value long enough that no timestamp or other output contains it by chance.
	const value = "918273645091827364"
	s := Secret(value)
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		out = append(out, fmt.Sprintf(verb, s))
	}
	out = append(out, s.String(), s.GoString())

	var buf bytes.Buffer
	noTime := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}
	slog.New(slog.NewJSONHandler(&buf, noTime)).Info("m", "otp", s)
	slog.New(slog.NewTextHandler(&buf, noTime)).Info("m", "otp", s)
	out = append(out, buf.String())

	j, err := json.Marshal(struct{ S Secret }{s})
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, string(j))

	for _, o := range out {
		if strings.Contains(o, value) || strings.Contains(o, fmt.Sprintf("%x", value)) ||
			strings.Contains(o, base64.StdEncoding.EncodeToString([]byte(value))) || !strings.Contains(o, "[redacted]") {
			t.Errorf("formatted secret %q: want [redacted] and no trace of the value", o)
		}
	}
}
