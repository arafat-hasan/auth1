package pgtest

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // the pgx database/sql driver
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	deploypg "github.com/arafat-hasan/auth1/deploy/postgres"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres/migrate"
	"github.com/arafat-hasan/auth1/migrations"
)

// Image is the PostgreSQL image the containers run.
const Image = "postgres:18-alpine"

// The roles of TDD-01 §4.1, which deploy/postgres/roles.sql creates in every container.
const (
	Migrator = "auth1_migrator" // runs the migrations and owns the schema
	App      = "auth1_app"      // the service at run time
)

// rolePassword is the password both roles get in a test container.
const rolePassword = "pgtest"

// bootstrapName is the database the roles script has run in; Empty copies it, and so does the
// template.
const bootstrapName = "t_bootstrap"

// templateName is the database that holds the migrated schema; DSN copies it.
const templateName = "t_template"

// requireDockerEnv, set to 1, turns a missing Docker into a test failure.
const requireDockerEnv = "AUTH1_REQUIRE_DOCKER"

// startTimeout bounds starting a container and waiting for it to accept connections.
const startTimeout = 2 * time.Minute

// stopTimeout bounds removing the shared container when the test binary ends.
const stopTimeout = time.Minute

// The package's shared container and Docker health, each found once per test binary. Main
// removes the container after the tests; the testcontainers reaper is only a fallback for a binary
// that dies before Main returns, since it relies on seeing its client disconnect, and some Docker
// hosts' port proxy never passes the disconnect on.
var (
	inMain atomic.Bool

	dockerOnce   sync.Once
	dockerHealth error

	sharedOnce sync.Once
	sharedInst *instance
	sharedErr  error

	dbCounter atomic.Int64
)

// instance is a running container with an admin connection to its postgres database.
type instance struct {
	ctr   *tcpostgres.PostgresContainer
	base  url.URL // DSN of the postgres database, sslmode=disable
	admin *sql.DB

	mu sync.Mutex // serialises CREATE DATABASE from one template

	bootstrapOnce sync.Once
	bootstrapErr  error

	templateOnce sync.Once
	templateErr  error
}

// Main runs the package's tests and then removes its shared container. Each test package that uses
// DSN or Empty calls it from its TestMain:
//
//	func TestMain(m *testing.M) { pgtest.Main(m) }
//
// A failure to remove the container fails the run, so a leak is not missed.
func Main(m *testing.M) {
	inMain.Store(true)
	code := m.Run()
	if err := stopShared(); err != nil {
		fmt.Fprintf(os.Stderr, "pgtest: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// stopShared closes the shared container's admin connection and removes the container, if the
// package started one. It runs after every test has ended.
func stopShared() error {
	if sharedInst == nil {
		return nil
	}
	_ = sharedInst.admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	if err := sharedInst.ctr.Terminate(ctx); err != nil {
		return fmt.Errorf("remove %s container: %w", Image, err)
	}
	return nil
}

// DSN returns the superuser DSN of a new database with every migration in migrations.FS applied,
// dropped when the test ends. The migrations run once per test package, as Migrator, on a template
// database. As gives the DSN of another role.
func DSN(t testing.TB) string {
	t.Helper()
	in := bootstrapped(t)
	in.templateOnce.Do(func() { in.templateErr = in.migrateTemplate() })
	if in.templateErr != nil {
		t.Fatalf("pgtest: %v", in.templateErr)
	}
	return in.create(t, templateName)
}

// Empty returns the superuser DSN of a new database with no tables, dropped when the test ends.
// The roles script has run in it: Migrator owns the public schema and App may only use it.
func Empty(t testing.TB) string {
	t.Helper()
	return bootstrapped(t).create(t, bootstrapName)
}

// As returns dsn with role, Migrator or App, as its user.
func As(t testing.TB, dsn, role string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("pgtest: parse DSN: %v", err)
	}
	u.User = url.UserPassword(role, rolePassword)
	return u.String()
}

// bootstrapped returns the package's container once the roles script has run in it.
func bootstrapped(t testing.TB) *instance {
	t.Helper()
	in := shared(t)
	in.bootstrapOnce.Do(func() { in.bootstrapErr = in.bootstrap() })
	if in.bootstrapErr != nil {
		t.Fatalf("pgtest: %v", in.bootstrapErr)
	}
	return in
}

// shared returns the package's container, starting it on first use. It fails t when the package's
// TestMain does not call Main, since nothing would then remove the container.
func shared(t testing.TB) *instance {
	t.Helper()
	if !inMain.Load() {
		t.Fatal("pgtest: the test package's TestMain must call pgtest.Main")
	}
	checkDocker(t)
	sharedOnce.Do(func() { sharedInst, sharedErr = start() })
	if sharedErr != nil {
		t.Fatalf("pgtest: %v", sharedErr)
	}
	return sharedInst
}

// checkDocker skips or fails t when Docker is not reachable.
func checkDocker(t testing.TB) {
	t.Helper()
	dockerOnce.Do(func() {
		p, err := testcontainers.NewDockerProvider()
		if err != nil {
			dockerHealth = err
			return
		}
		defer func() { _ = p.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dockerHealth = p.Health(ctx)
	})
	switch skip, fail := gate(dockerHealth, os.Getenv(requireDockerEnv) == "1"); {
	case fail:
		t.Fatalf("pgtest: Docker unavailable and %s=1: %v", requireDockerEnv, dockerHealth)
	case skip:
		t.Skipf("pgtest: Docker unavailable (set %s=1 to fail): %v", requireDockerEnv, dockerHealth)
	}
}

// gate decides what a test does given Docker's health: run, skip, or fail when Docker is required.
func gate(health error, require bool) (skip, fail bool) {
	if health == nil {
		return false, false
	}
	return !require, require
}

// start runs a container tuned for tests and opens an admin connection to it. On an error it
// removes the container and closes the connection itself, since the caller gets no instance.
func start() (in *instance, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	ctr, err := tcpostgres.Run(ctx, Image,
		tcpostgres.BasicWaitStrategies(),
		testcontainers.WithCmd("postgres", "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"),
	)
	if ctr != nil {
		defer func() {
			if err != nil {
				_ = ctr.Terminate(context.Background())
			}
		}()
	}
	if err != nil {
		return nil, fmt.Errorf("start %s: %w", Image, err)
	}
	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, fmt.Errorf("connection string: %w", err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %w", err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := admin.PingContext(ctx); err != nil {
		_ = admin.Close()
		return nil, fmt.Errorf("ping %s: %w", Image, err)
	}
	return &instance{ctr: ctr, base: *u, admin: admin}, nil
}

// bootstrap creates the bootstrap database, runs the roles script in it as a DBA would, and sets
// the roles' passwords. Its connection is closed afterwards, so the database can be copied.
func (in *instance) bootstrap() error {
	if _, err := in.admin.Exec("CREATE DATABASE " + bootstrapName + " TEMPLATE template0"); err != nil {
		return fmt.Errorf("create bootstrap database: %w", err)
	}
	db, err := sql.Open("pgx", in.dsn(bootstrapName))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(deploypg.RolesSQL); err != nil {
		return fmt.Errorf("roles script: %w", err)
	}
	for _, role := range []string{Migrator, App} {
		if _, err := db.Exec("ALTER ROLE " + role + " PASSWORD '" + rolePassword + "'"); err != nil {
			return fmt.Errorf("set the password of %s: %w", role, err)
		}
	}
	return nil
}

// migrateTemplate creates the template database and applies the migrations to it as Migrator. Its
// connection is closed afterwards, since PostgreSQL copies only a template nobody is connected to.
func (in *instance) migrateTemplate() error {
	if _, err := in.admin.Exec("CREATE DATABASE " + templateName + " TEMPLATE " + bootstrapName); err != nil {
		return fmt.Errorf("create template: %w", err)
	}
	u := in.base
	u.Path = "/" + templateName
	u.User = url.UserPassword(Migrator, rolePassword)
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if _, err := migrate.New(db, migrations.FS).Up(context.Background()); err != nil {
		return fmt.Errorf("migrate template: %w", err)
	}
	return nil
}

// create makes a database from template and returns its DSN. The database is dropped, with any
// connection still open to it, when the test ends.
func (in *instance) create(t testing.TB, template string) string {
	t.Helper()
	name := fmt.Sprintf("t_%d", dbCounter.Add(1))
	in.mu.Lock()
	_, err := in.admin.Exec("CREATE DATABASE " + name + " TEMPLATE " + template)
	in.mu.Unlock()
	if err != nil {
		t.Fatalf("pgtest: create database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := in.admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"); err != nil {
			t.Errorf("pgtest: drop database %s: %v", name, err)
		}
	})
	return in.dsn(name)
}

// dsn returns the DSN of the named database.
func (in *instance) dsn(name string) string {
	u := in.base
	u.Path = "/" + name
	return u.String()
}
