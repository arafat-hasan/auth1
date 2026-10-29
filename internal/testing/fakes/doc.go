// Package fakes holds deterministic implementations of the app.Clock and app.IDGenerator ports for
// tests (TDD-08 §9, TDD-01 §1). Only test files import it. The fakes never move on their own: the
// clock moves when the test sets or advances it, and the ids follow a fixed sequence.
package fakes
