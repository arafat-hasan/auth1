package account

import (
	"time"

	"github.com/google/uuid"
)

// Bucket is a sign-in throttle bucket of an account (TDD-07 §4): UntrustedBucket, or a known
// device's DeviceBucket. Failures count, and delays apply, per bucket.
type Bucket string

// UntrustedBucket is the bucket of sign-ins from no known device.
const UntrustedBucket Bucket = "untrusted"

// DeviceBucket is the bucket of the known device id: "device:<id>".
func DeviceBucket(id uuid.UUID) Bucket { return Bucket("device:" + id.String()) }

// ThrottlePolicy is L-3, rate_limits.sign_in_failures (TDD-07 §2): from the Threshold-th failure,
// a delay that starts at FirstDelay and doubles with each failure, up to MaxDelay.
type ThrottlePolicy struct {
	Threshold  int
	FirstDelay time.Duration
	MaxDelay   time.Duration
}

// Delay returns the delay after failures failures in a row: 0 below the threshold, then
// FirstDelay · 2^(failures − Threshold), capped at MaxDelay.
func (p ThrottlePolicy) Delay(failures int) time.Duration {
	if failures < p.Threshold || p.FirstDelay <= 0 {
		return 0
	}
	d := p.FirstDelay
	for range failures - p.Threshold {
		if d >= p.MaxDelay {
			break
		}
		d *= 2
	}
	return min(d, p.MaxDelay)
}
