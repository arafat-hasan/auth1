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

	"github.com/arafat-hasan/auth1/internal/adapters/postgres/migrate"
	"github.com/arafat-hasan/auth1/migrations"
)

// Image is the PostgreSQL image the containers run.
const Image = "postgres:18-alpine"

// templateName is the database that holds the migrated schema; DSN copies it.
const templateName = "t_template"

// requireDockerEnv, set to 1, turns a missing Docker into a test failure.
const requireDockerEnv = "AUTH1_REQUIRE_DOCKER"

// startTimeout bounds starting a container and waiting for it to accept connections.
const startTimeout = 2 * time.Minute

// The package's shared container and Docker health, each found once per test binary. The
// testcontainers reaper removes the container when the binary exits.
var (
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

	templateOnce sync.Once
	templateErr  error
}

// DSN returns the DSN of a new database with every migration in migrations.FS applied, dropped
// when the test ends. The migrations run once per test package, on a template database.
func DSN(t testing.TB) string {
	t.Helper()
	in := shared(t)
	in.templateOnce.Do(func() { in.templateErr = in.migrateTemplate() })
	if in.templateErr != nil {
		t.Fatalf("pgtest: %v", in.templateErr)
	}
	return in.create(t, templateName)
}

// Empty returns the DSN of a new, empty database, dropped when the test ends.
func Empty(t testing.TB) string {
	t.Helper()
	return shared(t).create(t, "template0")
}

// shared returns the package's container, starting it on first use.
func shared(t testing.TB) *instance {
	t.Helper()
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

// migrateTemplate creates the template database and applies the migrations to it. Its connection
// is closed afterwards, since PostgreSQL copies only a template nobody is connected to.
func (in *instance) migrateTemplate() error {
	if _, err := in.admin.Exec("CREATE DATABASE " + templateName + " TEMPLATE template0"); err != nil {
		return fmt.Errorf("create template: %w", err)
	}
	db, err := sql.Open("pgx", in.dsn(templateName))
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
