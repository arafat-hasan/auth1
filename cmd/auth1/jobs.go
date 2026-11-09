package main

import (
	"log/slog"
	"time"

	"github.com/uptrace/bun"
	"go.opentelemetry.io/otel/trace"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/adapters/postgres"
	"github.com/arafat-hasan/auth1/internal/adapters/system"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/telemetry"
	"github.com/arafat-hasan/auth1/internal/worker/jobs"
)

// The advisory lock ids of the leader-elected jobs (TDD-08 §7). An id is never reused. Reserved:
// 2 successor erasure, 3 purge, 4 audit detail clearing, 5 audit partitions, 6 bootstrap.
const lockFlowExpiry int32 = 1

// flowExpiryEvery is the flow-expiry job's interval (TDD-08 §7).
const flowExpiryEvery = time.Minute

// jobParts are what the jobs are built from.
type jobParts struct {
	cfg     *config.Config
	db      *bun.DB
	keys    *cryptoKeys
	metrics *telemetry.Metrics
	tracing trace.TracerProvider
	logger  *slog.Logger
	// every, when above 0, replaces the interval of every periodic job (tests); a once job stays
	// once.
	every time.Duration
}

// newJobs builds the leader-elected jobs and the leader connection that elects them (TDD-08 §7,
// §8). The caller runs the scheduler and closes the leader after it has stopped.
func newJobs(p jobParts) (*jobs.Scheduler, *postgres.Leader, error) {
	leader, err := postgres.NewLeader(p.cfg.Database, p.cfg.App.Environment, p.logger)
	if err != nil {
		return nil, nil, err
	}
	bidx, err := crypto.NewBlindIndex(p.keys.blindIndex)
	if err != nil {
		return nil, nil, err
	}
	fc := crypto.NewFieldCrypto(p.keys.fields)
	flows := postgres.NewFlows(p.db, fc, bidx)
	expiry, err := app.NewFlowExpiry(app.FlowExpiryDeps{
		UnitOfWork: postgres.NewUnitOfWork(p.db, p.cfg.Database.AcquireTimeout, p.tracing),
		Accounts:   postgres.NewAccounts(p.db, fc, bidx), Flows: flows, Expiring: flows,
		Outbox: postgres.NewOutbox(p.db, system.UUIDv7{}), Audit: postgres.NewAudit(p.db), Logger: p.logger,
	}, app.DefaultExpiryBatch)
	if err != nil {
		return nil, nil, err
	}
	lastSuccess, err := p.metrics.Gauge("auth1_job_last_success_timestamp")
	if err != nil {
		return nil, nil, err
	}
	every := func(d time.Duration) time.Duration {
		if p.every > 0 && d > 0 {
			return p.every
		}
		return d
	}
	sched, err := jobs.New(jobs.Options{
		Elector: leader, Logger: p.logger, LastSuccess: lastSuccess,
		Jobs: []jobs.Job{
			{Name: app.FlowExpiryJob, Lock: lockFlowExpiry, Every: every(flowExpiryEvery), Run: expiry.Run},
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return sched, leader, nil
}
