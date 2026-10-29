package argon2id

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
)

// newDummy hashes a random password with params under key: the dummy that VerifyDummy checks
// against (TDD-03 §1.4 step 4). Nobody knows its password.
func newDummy(key crypto.Key, params Params) (phc, error) {
	v := phc{params: params}
	password := make([]byte, 32)
	defer clear(password)
	if _, err := rand.Read(password); err != nil {
		return v, fmt.Errorf("argon2id: dummy: %w", err)
	}
	if _, err := rand.Read(v.salt[:]); err != nil {
		return v, fmt.Errorf("argon2id: dummy: %w", err)
	}
	sum := compute(key, params, v.salt[:], password)
	copy(v.hash[:], sum)
	clear(sum)
	return v, nil
}

// VerifyDummy implements app.PasswordHasher. It peppers under the current active key rather than
// the one the dummy was made under, so a pepper key removed since start-up cannot make it fail or
// skip the work; it answers false either way.
func (h *Hasher) VerifyDummy(_ context.Context, password []byte) (bool, error) {
	_, key := h.peppers.Current().Active()
	sum := compute(key, h.dummy.params, h.dummy.salt[:], password)
	_ = subtle.ConstantTimeCompare(sum, h.dummy.hash[:])
	clear(sum)
	return false, nil
}
