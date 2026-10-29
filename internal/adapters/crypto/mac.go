package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
)

// MAC computes the stored MACs of OTPs and recovery codes under the MAC key (TDD-01 §3.3):
//
//	OTP:           HMAC-SHA256(mac_key, "otp|" ‖ challenge_id ‖ "|" ‖ code)
//	recovery code: HMAC-SHA256(mac_key, "rcode|" ‖ account_id ‖ "|" ‖ code)
//
// with ids in canonical lower-case hyphenated form. It implements app.MAC and is safe for
// concurrent use.
type MAC struct {
	key Key
}

// NewMAC returns the MAC under key (encryption.mac_key_file). The zero Key is refused.
func NewMAC(key Key) (*MAC, error) {
	if key.isZero() {
		return nil, fmt.Errorf("MAC: %w", errKeyZero)
	}
	return &MAC{key: key}, nil
}

// OTP returns the MAC of a one-time code sent for the challenge challengeID (TDD-02 §2.2).
func (m *MAC) OTP(challengeID uuid.UUID, code []byte) []byte {
	return m.sum("otp|", challengeID, code)
}

// RecoveryCode returns the MAC of a normalised recovery code of the account accountID
// (TDD-03 §3.2).
func (m *MAC) RecoveryCode(accountID uuid.UUID, code []byte) []byte {
	return m.sum("rcode|", accountID, code)
}

// sum is HMAC-SHA256(key, prefix ‖ id ‖ "|" ‖ code).
func (m *MAC) sum(prefix string, id uuid.UUID, code []byte) []byte {
	h := hmac.New(sha256.New, m.key.b()[:])
	h.Write([]byte(prefix + id.String() + "|"))
	h.Write(code)
	return h.Sum(nil)
}
