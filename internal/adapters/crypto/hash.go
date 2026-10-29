package crypto

import "crypto/sha256"

// SHA256 returns the SHA-256 of b, the stored form of link tokens, flow handles and refresh tokens
// (TDD-01 §3.3). They are 256 random bits, so they need no key.
func SHA256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
