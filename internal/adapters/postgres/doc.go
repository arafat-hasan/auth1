// Package postgres implements the repositories and the unit of work on PostgreSQL
// (TDD-01 §4, §4.2, §6, TDD-08 §2). Accounts is the repository of the account aggregate; it
// encrypts through app.FieldCrypto and writes its conditional updates as explicit SQL.
package postgres
