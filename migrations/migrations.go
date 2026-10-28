package migrations

import "embed"

// FS holds the migration files. It embeds the whole directory, because a pattern such as *.sql
// does not compile while the directory has no migration; the runner ignores files that are not
// SQL.
//
//go:embed *
var FS embed.FS
