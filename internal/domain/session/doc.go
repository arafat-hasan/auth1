// Package session holds the plaintext records of sessions and their refresh tokens as the
// sessions repository stores them (TDD-01 §4, TDD-04 §2, §3), and the reasons a session is
// revoked. It does no I/O: token hashes are computed by the caller.
package session
