// Package pgtest runs PostgreSQL 18 in containers for repository tests (TDD-08 §9). Only test
// files import it. A test package shares one container; each test gets its own database. The
// package's TestMain calls Main, which removes the shared container after the tests.
//
// Each container is bootstrapped as production is: deploy/postgres/roles.sql creates the Migrator and
// App roles, and the migrations run as Migrator. DSN and Empty return superuser DSNs; As gives the
// same database as another role.
//
// When Docker is not reachable, the helpers skip the test, unless AUTH1_REQUIRE_DOCKER=1, in which
// case they fail it. CI sets the variable.
package pgtest
