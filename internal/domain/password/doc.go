// Package password holds the password policy (TDD-03 §2): the length bounds, the identifier check
// and the deny-list, with the reasons of PASSWORD_REJECTED. Passwords stay []byte. It is pure: the
// deny-list is parsed from a reader that the caller opens.
package password
