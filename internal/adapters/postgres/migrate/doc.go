// Package migrate applies, reverts and reports the plain SQL schema migrations, numbered
// NNNNNN_<name>.up.sql and .down.sql, under a PostgreSQL advisory lock (TDD-01 §4.3, TDD-08 §1).
package migrate
