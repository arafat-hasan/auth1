// Package jobs runs the leader-elected jobs of TDD-08 §7: each job runs at its interval on the
// one instance that holds its advisory lock (postgres.Leader), and records
// auth1_job_last_success_timestamp{job} after each successful run.
package jobs
