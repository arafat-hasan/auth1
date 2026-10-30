// Package identifier holds the identifier types (TDD-01 §2, SDD D-3): the registry of types and
// their policies, checked at start-up, and the email and phone types with their normalisation and
// the variants a password must not contain. It is pure: no DNS look-up and no I/O.
package identifier
