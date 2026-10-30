// Package postgres implements the repositories and the unit of work on PostgreSQL
// (TDD-01 §4, §4.2, §6, TDD-06 §1–§2, TDD-08 §2). Accounts is the repository of the account
// aggregate; it encrypts through app.FieldCrypto and writes its conditional updates as explicit
// SQL. Flows is the repository of the flow aggregate, flows with their challenges (TDD-02 §2,
// TDD-07 §5): finders lock nothing, LockFlow and LockChallenges lock in the order account, flow,
// challenge, and the transaction records the locks so methods refuse to run out of order. Outbox
// and Audit write the outbox and the audit log in the use case's transaction, and
// UnitOfWork moves the version of each account locked in it before committing.
package postgres
