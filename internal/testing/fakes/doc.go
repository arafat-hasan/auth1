// Package fakes holds deterministic implementations of app ports for tests (TDD-08 §9): the
// app.Clock and app.IDGenerator (TDD-01 §1), the app.RateLimiter (TDD-07 §1) and a signing keyring
// implementing app.TokenSigner and app.PublicKeys (TDD-04 §5). Only test files import it. The fakes
// never move on their own: the clock moves when the test sets or advances it, the ids follow a
// fixed sequence, and the keyring changes only through its setters.
package fakes
