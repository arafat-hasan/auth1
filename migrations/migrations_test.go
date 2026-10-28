package migrations_test

import (
	"testing"

	"github.com/arafat-hasan/auth1/internal/adapters/postgres/migrate"
	"github.com/arafat-hasan/auth1/migrations"
)

// TestLoad fails when a file in this directory is misnamed or a down file lacks its up file.
func TestLoad(t *testing.T) {
	t.Parallel()
	if _, err := migrate.Load(migrations.FS); err != nil {
		t.Fatal(err)
	}
}
