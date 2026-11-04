package idempotency

import (
	"crypto/sha256"
	"fmt"

	"github.com/gowebpki/jcs"
)

// RequestHash returns sha256(method ‖ 0x00 ‖ escapedPath ‖ 0x00 ‖ JCS(body)), the request hash of
// TDD-05 §4. An empty body adds nothing after the second separator; any other body must be
// I-JSON, which RFC 8785 canonicalises: a duplicate member, invalid UTF-8 or trailing data is an
// error. escapedPath is the request path as sent, so a %00 in it stays three characters.
func RequestHash(method, escapedPath string, body []byte) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(escapedPath))
	h.Write([]byte{0})
	if len(body) > 0 {
		canonical, err := jcs.Transform(body)
		if err != nil {
			return nil, fmt.Errorf("canonicalise the body: %w", err)
		}
		h.Write(canonical)
	}
	return h.Sum(nil), nil
}
