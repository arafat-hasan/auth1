package app

import "github.com/google/uuid"

// MAC computes the stored form of short secrets under the MAC key (SDD D-18, TDD-01 §3.3). OTP is
// the MAC of a one-time code bound to its challenge (TDD-02 §2.2); RecoveryCode is the MAC of a
// normalised recovery code bound to its account (TDD-03 §3.2). The two are domain-separated, so
// one never equals the other. Callers compare results in constant time.
type MAC interface {
	OTP(challengeID uuid.UUID, code []byte) []byte
	RecoveryCode(accountID uuid.UUID, code []byte) []byte
}
