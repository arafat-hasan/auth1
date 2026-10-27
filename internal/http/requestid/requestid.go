package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// Header carries the request id: auth1's own on the response, the caller's on the request.
const Header = "X-Request-Id"

// maxUpstreamLen is the longest incoming id that is kept.
const maxUpstreamLen = 64

type ctxKey struct{}

type ids struct {
	own, upstream string
}

// Middleware generates a request id (16 random bytes, hex), sets it on the response and stores it,
// with an acceptable incoming id, in the request context.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := ids{own: newID(), upstream: upstream(r.Header.Values(Header))}
		w.Header().Set(Header, v.own)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, v)))
	})
}

// From returns the request id auth1 generated, or "" outside Middleware.
func From(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(ids)
	return v.own
}

// UpstreamFrom returns the caller's X-Request-Id when it was a single value of 1 to 64 visible
// ASCII characters, or "".
func UpstreamFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(ids)
	return v.upstream
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error
	return hex.EncodeToString(b[:])
}

// upstream returns the single incoming value when it is acceptable, else "".
func upstream(values []string) string {
	if len(values) != 1 {
		return ""
	}
	v := values[0]
	if v == "" || len(v) > maxUpstreamLen {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return ""
		}
	}
	return v
}
