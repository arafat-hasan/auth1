package app

import "errors"

// ErrBlindIndexType is returned for an identifier type that is empty or contains a 0x00 byte,
// which would make the index input ambiguous.
var ErrBlindIndexType = errors.New("blind index type invalid")

// BlindIndex finds encrypted identifiers by equality (SDD D-18, TDD-01 §3.2). Compute returns the
// 32-byte index of an identifier's normalised value under its type. It is deterministic under one
// key, so an index stays valid across restarts and releases.
type BlindIndex interface {
	Compute(idType string, normalised []byte) ([]byte, error)
}
