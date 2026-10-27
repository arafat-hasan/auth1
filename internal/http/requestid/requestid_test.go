package requestid

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// serve runs Middleware around a handler that records From and UpstreamFrom.
func serve(t *testing.T, incoming string) (header, inside, upstream string) {
	t.Helper()
	h := Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		inside = From(r.Context())
		upstream = UpstreamFrom(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if incoming != "" {
		req.Header.Set(Header, incoming)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Header().Get(Header), inside, upstream
}

func TestRequestID(t *testing.T) {
	t.Parallel()

	header, inside, _ := serve(t, "abc")
	if !idPattern.MatchString(header) {
		t.Errorf("response id %q is not 32 lower-case hex characters", header)
	}
	if inside != header {
		t.Errorf("From = %q, response header = %q", inside, header)
	}
	other, _, _ := serve(t, "")
	if other == header {
		t.Errorf("two requests got the same id %q", header)
	}
}

func TestUpstreamRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, incoming, want string
	}{
		{"absent", "", ""},
		{"plain", "abc-123", "abc-123"},
		{"64 characters", strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{"65 characters", strings.Repeat("a", 65), ""},
		{"space", "a b", ""},
		{"delete", "a\x7fb", ""},
		{"non-ASCII", "aéb", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			header, _, upstream := serve(t, tt.incoming)
			if upstream != tt.want {
				t.Errorf("UpstreamFrom = %q, want %q", upstream, tt.want)
			}
			if header == tt.incoming {
				t.Error("the incoming id was returned as auth1's own")
			}
		})
	}
}

func TestUpstreamControlCharacter(t *testing.T) {
	t.Parallel()

	// Header.Set would refuse these, so set the map directly, as a raw request would.
	for _, v := range []string{"a\nb", "a\x00b", "a\tb"} {
		h := Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if got := UpstreamFrom(r.Context()); got != "" {
				t.Errorf("UpstreamFrom = %q for %q", got, v)
			}
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header[Header] = []string{v}
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
}

func TestFromWithoutMiddleware(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if From(req.Context()) != "" || UpstreamFrom(req.Context()) != "" {
		t.Error("ids present without the middleware")
	}
}

func TestUpstreamSeveralValues(t *testing.T) {
	t.Parallel()

	h := Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if got := UpstreamFrom(r.Context()); got != "" {
			t.Errorf("UpstreamFrom = %q for two values", got)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add(Header, "a")
	req.Header.Add(Header, "b")
	h.ServeHTTP(httptest.NewRecorder(), req)
}
