package argon2id

import (
	"context"
	"time"

	"github.com/arafat-hasan/auth1/internal/adapters/crypto"
	"github.com/arafat-hasan/auth1/internal/app"
)

// run waits for a hashing slot, then computes Argon2id for password with params, salt and key
// (SDD D-7, TDD-03 §1.4 step 1). With every slot taken for QueueTimeout it returns
// app.ErrOverloaded, counted in auth1_hash_rejected_total; if ctx ends first, ctx's error. The
// wait is recorded in auth1_hash_queue_seconds either way, and the computation alone in
// auth1_hash_duration_seconds.
func (h *Hasher) run(ctx context.Context, key crypto.Key, params Params, salt, password []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	start := time.Now()
	select {
	case h.slots <- struct{}{}:
	default:
		timer := time.NewTimer(h.queueTimeout)
		defer timer.Stop()
		select {
		case h.slots <- struct{}{}:
		case <-timer.C:
			h.recordQueue(ctx, start)
			if h.rejected != nil {
				h.rejected.Add(ctx, 1)
			}
			return nil, app.ErrOverloaded
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	defer func() { <-h.slots }()
	h.recordQueue(ctx, start)
	start = time.Now()
	sum := h.compute(key, params, salt, password)
	if h.duration != nil {
		h.duration.Record(ctx, time.Since(start).Seconds())
	}
	return sum, nil
}

// recordQueue records the wait since start in auth1_hash_queue_seconds.
func (h *Hasher) recordQueue(ctx context.Context, start time.Time) {
	if h.queue != nil {
		h.queue.Record(ctx, time.Since(start).Seconds())
	}
}
