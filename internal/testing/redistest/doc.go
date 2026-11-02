// Package redistest runs Redis in containers for the rate-limiter tests (TDD-08 §9). Only test
// files import it. A test package shares one container, and each test takes a key prefix of its
// own from Prefix; NewServer gives a container that a test can stop and start. The package's
// TestMain calls Main, which removes the shared container after the tests.
//
// When Docker is not reachable, the helpers skip the test, unless AUTH1_REQUIRE_DOCKER=1, in which
// case they fail it. CI sets the variable.
package redistest
