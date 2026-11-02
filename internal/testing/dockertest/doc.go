// Package dockertest holds what the container helpers share (TDD-08 §9): the gate that skips a
// test without Docker, or fails it when AUTH1_REQUIRE_DOCKER=1, and a TCP proxy that keeps a
// container's address stable across a restart. Only test files import it.
package dockertest
