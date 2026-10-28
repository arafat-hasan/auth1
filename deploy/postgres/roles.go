package postgres

import _ "embed" // for RolesSQL

// RolesSQL is roles.sql: it creates auth1_migrator and auth1_app if they are missing and gives
// auth1_migrator the public schema of the database it runs in. Tests run it as a superuser.
//
//go:embed roles.sql
var RolesSQL string
