// Package flow holds the pure rules of flows and challenges (SDD D-4, TDD-02 §2): the flow kinds
// and their lifetimes, the typed non-secret state of each kind, secret generation, and the
// verification and resend decisions over a challenge; the amr of a sign-in (TDD-03 §7); and the
// plaintext records the flows repository stores (TDD-01 §4). It
// does no I/O: the caller passes in the time, the configured limits and a source of randomness,
// and computes MACs and hashes itself.
package flow
